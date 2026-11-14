#
# SPDX-License-Identifier: Apache-2.0
"""Intra-procedural taint analysis.

This module provides a whole-module, statement-ordered taint analysis that
runs *before* the regular bandit node visitor dispatches plugins.  Plugins and
the visitor can query the taint state of any AST expression node through
:class:`TaintAnalysis` instead of re-deriving data flow ad-hoc inside a single
plugin check.

The analysis is deliberately intra-procedural and conservative:

* taint is tracked per function scope with symbolic parameter taint;
* local function calls are resolved via per-function return summaries;
* anything that cannot be resolved is reported as *unknown*, which leaves
  callers free to fall back to bandit's traditional literal-based heuristics
  instead of silently clearing a potentially tainted path.

Configuration (all optional, merged onto the defaults below) is supplied as
the ``taint_analysis`` mapping in bandit's config:

.. code-block:: yaml

    taint_analysis:
      sources:
        - flask.request
        - django.http.HttpRequest
        - sys.argv
        - input
      sanitizers:
        - shlex.quote
      validators:
        - allow
        - validate
        - sanitize
"""
import ast
import copy
import fnmatch
import logging

LOG = logging.getLogger(__name__)

# State sentinels.  ``None`` means "unknown" (the analysis cannot prove where
# the value came from); ``CLEAN`` means "provably derived from constants only".
class TaintState:
    """Taint state attached to an AST expression node.

    :param tainted: whether the value carries untrusted data
    :param origins: frozenset of human readable origin descriptors
    """

    __slots__ = ("tainted", "origins")

    def __init__(self, tainted, origins=frozenset()):
        self.tainted = tainted
        if not isinstance(origins, frozenset):
            origins = frozenset(origins)
        self.origins = origins

    def __repr__(self):
        kind = "tainted" if self.tainted else "clean"
        return f"TaintState({kind}, {sorted(self.origins)!r})"

    def __eq__(self, other):
        if not isinstance(other, TaintState):
            return NotImplemented
        return (
            self.tainted == other.tainted and self.origins == other.origins
        )

    def __hash__(self):
        return hash((self.tainted, self.origins))


# Provably constant-derived value.
CLEAN = TaintState(False)

DEFAULT_CONFIG = {
    "sources": [
        "flask.request",
        "django.http.HttpRequest",
        "sys.argv",
        "input",
    ],
    "sanitizers": [
        "shlex.quote",
    ],
    "validators": [
        "allow",
        "allow_*",
        "validate",
        "validate_*",
        "is_valid",
        "is_*_valid",
        "sanitize",
        "sanitize*",
        "sanitise*",
        "whitelist*",
    ],
}

# Keyword arguments that carry the bound parameters of a parameterized
# database query (DBAPI uses positional args, but wrappers vary).
_QUERY_PARAM_KWARGS = frozenset(("params", "parameters", "args"))
_EXECUTE_METHODS = frozenset(("execute", "executemany"))


class TaintConfig:
    """Resolved taint analysis configuration.

    User supplied lists override individual default keys; keys that are not
    provided keep their built-in defaults.
    """

    def __init__(self, config=None):
        merged = copy.deepcopy(DEFAULT_CONFIG)
        if config:
            for key in merged:
                value = config.get(key)
                if value:
                    merged[key] = list(value)
        self.sources = merged["sources"]
        self.sanitizers = merged["sanitizers"]
        self.validators = merged["validators"]
        # Bare names that are treated as request roots even when no import
        # alias can prove it (e.g. a Django view parameter called ``request``).
        self.root_names = self._derive_root_names()

    def _derive_root_names(self):
        roots = set()
        for source in self.sources:
            roots.add(source.rsplit(".", 1)[-1])
        roots.add("request")
        return roots

    @classmethod
    def default(cls):
        return cls()

    @staticmethod
    def _matches(patterns, *names):
        for name in names:
            if not name:
                continue
            bare = name.rsplit(".", 1)[-1]
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(
                    bare, pattern
                ):
                    return True
        return False

    def is_source(self, *names):
        source_roots = {
            source.rsplit(".", 1)[-1] for source in self.sources
        }
        for name in names:
            if self._matches(self.sources, name):
                return True
            # Tail prefixes and roots are sources too: "request.args"
            # matches the "flask.request" source just like an attribute
            # chain rooted at a request object.
            if name.split(".", 1)[0] in source_roots:
                return True
            tail = name.rsplit(".", 1)[0] if "." in name else ""
            while tail:
                if self._matches(self.sources, tail):
                    return True
                tail = tail.rsplit(".", 1)[0] if "." in tail else ""
        return False

    def is_sanitizer(self, *names):
        return self._matches(self.sanitizers, *names)

    def is_validator(self, *names):
        return self._matches(self.validators, *names)


class _Scope:
    """A single function/module scope with its mutable environment."""

    def __init__(self, node, parent=None):
        self.node = node
        self.parent = parent
        # binding key -> TaintState (or None for unknown)
        self.env = {}
        # collected TaintState for return statements
        self.returns = []
        # parameter name -> TaintState
        self.params = {}
        self.summary = None


def merge_states(states):
    """Merge states from converging control-flow paths.

    Any tainted state makes the result tainted; all-clean gives CLEAN; all
    unknown gives unknown (``None``).
    """
    known = [s for s in states if s is not None]
    if not known:
        return None
    origins = frozenset()
    tainted = False
    for state in known:
        if state.tainted:
            tainted = True
            origins |= state.origins
    if not tainted:
        return CLEAN
    return TaintState(True, origins)


def propagate_states(states):
    """Merge taint across operands of a single expression.

    Stricter than :func:`merge_states`: an unresolved (unknown) operand keeps
    the whole expression unknown, so callers can fall back to traditional
    heuristics instead of treating unproven data as clean.
    """
    if not states or all(state is None for state in states):
        return None
    origins = frozenset()
    for state in states:
        if state is not None and state.tainted:
            origins |= state.origins
    if origins:
        return TaintState(True, origins)
    if any(state is None for state in states):
        return None
    return CLEAN


class TaintAnalysis:
    """Result of running the intra-procedural taint analysis on a module."""

    def __init__(self, tree, config=None):
        self.tree = tree
        self.config = config if config is not None else TaintConfig.default()
        # AST node -> TaintState recorded at its (last) evaluation point
        self._node_states = {}
        self.import_aliases = {}
        self._func_defs = {}
        self._func_summaries = {}
        # guard against recursive helper functions during on-demand analysis
        self._funcs_in_progress = set()
        self._scopes = []
        self._analyze()

    # ------------------------------------------------------------------
    # Public query API used by the visitor and plugins
    # ------------------------------------------------------------------
    def get_state(self, node):
        """Return the TaintState for an expression node, or None."""
        if node is None:
            return None
        return self._node_states.get(node)

    def is_tainted(self, node):
        state = self.get_state(node)
        return state is not None and state.tainted

    def is_clean(self, node):
        return self.get_state(node) is CLEAN

    def origins(self, node):
        state = self.get_state(node)
        if state is None:
            return frozenset()
        return state.origins

    def callee_qualname(self, call_node):
        """Qualified name of the callee in a Call node (best effort)."""
        if not isinstance(call_node, ast.Call):
            return ""
        return self._callee_qualname(call_node)

    def callee_basename(self, call_node):
        """Unqualified callee name of a Call node (best effort)."""
        if not isinstance(call_node, ast.Call):
            return ""
        return self._callee_basename(call_node)

    def is_parameterized_execute(self, call_node):
        """True for ``execute``/``executemany`` calls with bound parameters.

        A parameterized query keeps the SQL text separate from the values, so
        a tainted value in the parameter slot is not an injection.  The query
        text itself must still be provably non-tainted.
        """
        if not isinstance(call_node, ast.Call):
            return False
        if self._callee_basename(call_node) not in _EXECUTE_METHODS:
            return False
        has_params = len(call_node.args) >= 2 or any(
            kw.arg in _QUERY_PARAM_KWARGS for kw in call_node.keywords
        )
        if not has_params or not call_node.args:
            return False
        query_state = self.get_state(call_node.args[0])
        return query_state is not None and not query_state.tainted

    # ------------------------------------------------------------------
    # Analysis driver
    # ------------------------------------------------------------------
    def _analyze(self):
        self._collect_imports(self.tree)
        self._collect_functions(self.tree)
        module_scope = _Scope(self.tree)
        self._module_scope = module_scope
        self._scopes.append(module_scope)
        for stmt in self.tree.body:
            self._walk_stmt(stmt, module_scope)
        self._scopes.pop()

    def _ensure_func_summary(self, func_node):
        """Return a function's return summary, analyzing it on demand.

        On-demand analysis supports forward references; the in-progress set
        breaks recursion cycles by leaving the unresolved call unknown.
        """
        if func_node in self._func_summaries:
            return self._func_summaries[func_node]
        if func_node in self._funcs_in_progress:
            return None
        self._analyze_function(func_node, self._module_scope)
        return self._func_summaries.get(func_node)

    def _collect_imports(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.import_aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                for alias in node.names:
                    bound = alias.asname or alias.name
                    self.import_aliases[bound] = (
                        node.module + "." + alias.name
                    )

    def _collect_functions(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._func_defs[node.name] = node

    # ------------------------------------------------------------------
    # Environment helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _var_key(name):
        return ("v", name)

    @staticmethod
    def _attr_key(base, attr):
        return ("a", base, attr)

    @staticmethod
    def _sub_key(base):
        return ("s", base)

    def _lookup(self, key, scope):
        current = scope
        while current is not None:
            if key in current.env:
                return current.env[key]
            current = current.parent
        return None

    def _bind(self, key, state, scope):
        scope.env[key] = state

    def _snapshot(self, scope):
        return dict(scope.env)

    def _restore(self, snapshot, scope):
        scope.env = dict(snapshot)

    def _merge_into(self, snapshot, scope):
        merged = {}
        keys = set(snapshot) | set(scope.env)
        for key in keys:
            merged[key] = merge_states(
                [snapshot.get(key), scope.env.get(key)]
            )
        scope.env = merged

    # ------------------------------------------------------------------
    # Statement walking
    # ------------------------------------------------------------------
    def _walk_stmts(self, stmts, scope):
        for stmt in stmts:
            self._walk_stmt(stmt, scope)

    def _walk_stmt(self, node, scope):
        method = "_stmt_" + type(node).__name__
        handler = getattr(self, method, None)
        if handler is not None:
            handler(node, scope)
        else:
            self._stmt_generic(node, scope)

    def _stmt_generic(self, node, scope):
        """Fallback: evaluate every nested expression and walk statements."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._walk_stmt(child, scope)
            elif isinstance(child, ast.expr):
                self._eval(child, scope)

    def _stmt_FunctionDef(self, node, scope):
        self._analyze_function(node, scope)

    def _stmt_AsyncFunctionDef(self, node, scope):
        self._analyze_function(node, scope)

    def _analyze_function(self, node, parent_scope):
        # The function object itself is not tainted data.
        self._bind(self._var_key(node.name), CLEAN, parent_scope)
        if node in self._func_summaries or node in self._funcs_in_progress:
            # Already analyzed (on-demand), or a recursion cycle.
            return
        self._funcs_in_progress.add(node)

        func_scope = _Scope(node, parent_scope)
        self._scopes.append(func_scope)

        args = node.args
        all_args = list(args.posonlyargs) + list(args.args)
        all_args += list(args.kwonlyargs)
        if args.vararg:
            all_args.append(args.vararg)
        if args.kwarg:
            all_args.append(args.kwarg)
        for arg in all_args:
            state = TaintState(True, {"param:" + arg.arg})
            func_scope.params[arg.arg] = state
            func_scope.env[self._var_key(arg.arg)] = state

        # Default values are evaluated in the enclosing scope.
        for default in args.defaults + args.kw_defaults:
            if default is not None:
                self._eval(default, parent_scope)

        self._walk_stmts(node.body, func_scope)
        func_scope.summary = merge_states(func_scope.returns)
        # Retain the summary outside the scope stack so calls can resolve
        # helper functions regardless of definition order or nesting.
        self._func_summaries[node] = func_scope.summary
        self._funcs_in_progress.discard(node)
        self._scopes.pop()

    def _stmt_ClassDef(self, node, scope):
        self._bind(self._var_key(node.name), CLEAN, scope)
        class_scope = _Scope(node, scope)
        self._scopes.append(class_scope)
        self._walk_stmts(node.body, class_scope)
        self._scopes.pop()

    def _stmt_Assign(self, node, scope):
        state = self._eval(node.value, scope)
        for target in node.targets:
            self._bind_target(target, state, scope)

    def _stmt_AnnAssign(self, node, scope):
        if node.value is not None:
            state = self._eval(node.value, scope)
            self._bind_target(node.target, state, scope)

    def _stmt_AugAssign(self, node, scope):
        current = self._eval_target(node.target, scope)
        value = self._eval(node.value, scope)
        self._bind_target(
            node.target, propagate_states([current, value]), scope
        )

    def _bind_target(self, target, state, scope):
        if isinstance(target, ast.Name):
            self._bind(self._var_key(target.id), state, scope)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    self._bind_target(elt.value, state, scope)
                else:
                    self._bind_target(elt, state, scope)
        elif isinstance(target, ast.Attribute) and isinstance(
            target.value, ast.Name
        ):
            self._bind(
                self._attr_key(target.value.id, target.attr), state, scope
            )
        elif isinstance(target, ast.Subscript) and isinstance(
            target.value, ast.Name
        ):
            # Container granularity: any element write taints the container.
            self._bind(self._sub_key(target.value.id), state, scope)

    def _eval_target(self, target, scope):
        if isinstance(target, ast.Name):
            return self._lookup(self._var_key(target.id), scope)
        if isinstance(target, ast.Attribute) and isinstance(
            target.value, ast.Name
        ):
            return self._lookup(
                self._attr_key(target.value.id, target.attr), scope
            )
        if isinstance(target, ast.Subscript) and isinstance(
            target.value, ast.Name
        ):
            return self._lookup(self._sub_key(target.value.id), scope)
        return self._eval(target, scope)

    def _stmt_Return(self, node, scope):
        if node.value is not None:
            state = self._eval(node.value, scope)
            scope.returns.append(state)

    def _stmt_Expr(self, node, scope):
        self._eval(node.value, scope)

    def _stmt_If(self, node, scope):
        self._eval(node.test, scope)
        snapshot = self._snapshot(scope)
        self._walk_stmts(node.body, scope)
        after_body = self._snapshot(scope)
        self._restore(snapshot, scope)
        self._walk_stmts(node.orelse, scope)
        # Merge both branches back together.
        merged = {}
        keys = set(after_body) | set(scope.env)
        for key in keys:
            merged[key] = merge_states(
                [after_body.get(key), scope.env.get(key)]
            )
        scope.env = merged

    def _stmt_While(self, node, scope):
        self._eval(node.test, scope)
        snapshot = self._snapshot(scope)
        self._walk_stmts(node.body, scope)
        self._merge_into(snapshot, scope)
        self._walk_stmts(node.orelse, scope)

    def _stmt_For(self, node, scope):
        iter_state = self._eval(node.iter, scope)
        self._bind_target(node.target, iter_state, scope)
        snapshot = self._snapshot(scope)
        self._walk_stmts(node.body, scope)
        self._merge_into(snapshot, scope)
        self._walk_stmts(node.orelse, scope)

    def _stmt_AsyncFor(self, node, scope):
        self._stmt_For(node, scope)

    def _stmt_With(self, node, scope):
        for item in node.items:
            state = self._eval(item.context_expr, scope)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars, state, scope)
        self._walk_stmts(node.body, scope)

    def _stmt_AsyncWith(self, node, scope):
        self._stmt_With(node, scope)

    def _stmt_Try(self, node, scope):
        snapshot = self._snapshot(scope)
        self._walk_stmts(node.body, scope)
        after_try = self._snapshot(scope)
        branches = [after_try]
        for handler in node.handlers:
            self._restore(snapshot, scope)
            if handler.type is not None:
                self._eval(handler.type, scope)
            if handler.name:
                # Exception objects are not user request data.
                self._bind(self._var_key(handler.name), CLEAN, scope)
            self._walk_stmts(handler.body, scope)
            branches.append(self._snapshot(scope))
        self._restore(snapshot, scope)
        self._walk_stmts(node.orelse, scope)
        branches.append(self._snapshot(scope))
        merged = {}
        for branch in branches:
            for key, state in branch.items():
                merged[key] = merge_states([merged.get(key), state])
        scope.env = merged
        # finally always executes on the merged state
        self._walk_stmts(node.finalbody, scope)

    def _stmt_Raise(self, node, scope):
        if node.exc is not None:
            self._eval(node.exc, scope)

    def _stmt_Assert(self, node, scope):
        self._eval(node.test, scope)
        if node.msg is not None:
            self._eval(node.msg, scope)

    def _stmt_Delete(self, node, scope):
        for target in node.targets:
            if isinstance(target, ast.Name):
                scope.env.pop(self._var_key(target.id), None)

    # ------------------------------------------------------------------
    # Expression evaluation
    # ------------------------------------------------------------------
    def _eval(self, node, scope):
        if node is None:
            return None
        method = "_eval_" + type(node).__name__
        handler = getattr(self, method, None)
        if handler is not None:
            state = handler(node, scope)
        else:
            state = None
        self._node_states[node] = state
        return state

    def _eval_Constant(self, node, scope):
        return CLEAN

    def _eval_Name(self, node, scope):
        key = self._var_key(node.id)
        state = self._lookup(key, scope)
        if state is not None:
            return state
        # Unbound name: treat known request roots / sources as taint sources.
        if node.id in self.config.root_names or self.config.is_source(node.id):
            return TaintState(True, {self._source_origin(node.id)})
        return None

    def _eval_Attribute(self, node, scope):
        qualname = self._qualname(node)
        # Source chains (flask.request.args, sys.argv, request.GET ...).
        if self._matches_source_chain(qualname):
            return TaintState(True, {self._source_origin(qualname)})
        base_state = self._eval(node.value, scope)
        tracked = None
        if isinstance(node.value, ast.Name):
            tracked = self._lookup(
                self._attr_key(node.value.id, node.attr), scope
            )
        state = propagate_states([base_state, tracked])
        return state

    def _eval_Subscript(self, node, scope):
        base_state = self._eval(node.value, scope)
        slice_state = self._eval_slice(node.slice, scope)
        tracked = None
        if isinstance(node.value, ast.Name):
            tracked = self._lookup(self._sub_key(node.value.id), scope)
        return propagate_states([base_state, slice_state, tracked])

    def _eval_slice(self, node, scope):
        if isinstance(node, ast.Slice):
            return propagate_states(
                [
                    self._eval(node.lower, scope),
                    self._eval(node.upper, scope),
                    self._eval(node.step, scope),
                ]
            )
        return self._eval(node, scope)

    def _eval_Starred(self, node, scope):
        return self._eval(node.value, scope)

    def _eval_UnaryOp(self, node, scope):
        return self._eval(node.operand, scope)

    def _eval_BinOp(self, node, scope):
        # Concatenation, %-formatting and arithmetic all propagate taint.
        return propagate_states(
            [self._eval(node.left, scope), self._eval(node.right, scope)]
        )

    def _eval_BoolOp(self, node, scope):
        return propagate_states(
            [self._eval(value, scope) for value in node.values]
        )

    def _eval_Compare(self, node, scope):
        states = [self._eval(node.left, scope)]
        for comparator in node.comparators:
            states.append(self._eval(comparator, scope))
        return propagate_states(states)

    def _eval_IfExp(self, node, scope):
        self._eval(node.test, scope)
        return propagate_states(
            [
                self._eval(node.body, scope),
                self._eval(node.orelse, scope),
            ]
        )

    def _eval_List(self, node, scope):
        return propagate_states(
            [self._eval(elt, scope) for elt in node.elts]
        )

    def _eval_Tuple(self, node, scope):
        return propagate_states(
            [self._eval(elt, scope) for elt in node.elts]
        )

    def _eval_Set(self, node, scope):
        return propagate_states(
            [self._eval(elt, scope) for elt in node.elts]
        )

    def _eval_Dict(self, node, scope):
        states = [self._eval(key, scope) for key in node.keys]
        states += [self._eval(value, scope) for value in node.values]
        return propagate_states(states)

    def _eval_JoinedStr(self, node, scope):
        states = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                states.append(self._eval(value.value, scope))
            else:
                states.append(self._eval(value, scope))
        return propagate_states(states)

    def _eval_FormattedValue(self, node, scope):
        return self._eval(node.value, scope)

    def _eval_ListComp(self, node, scope):
        return self._eval_comprehension(node, scope)

    def _eval_SetComp(self, node, scope):
        return self._eval_comprehension(node, scope)

    def _eval_GeneratorExp(self, node, scope):
        return self._eval_comprehension(node, scope)

    def _eval_DictComp(self, node, scope):
        states = [self._eval_comprehension_generators(node, scope)]
        states.append(self._eval(node.key, scope))
        states.append(self._eval(node.value, scope))
        return propagate_states(states)

    def _eval_comprehension(self, node, scope):
        states = [self._eval_comprehension_generators(node, scope)]
        states.append(self._eval(node.elt, scope))
        return propagate_states(states)

    def _eval_comprehension_generators(self, node, scope):
        states = []
        for generator in node.generators:
            states.append(self._eval(generator.iter, scope))
            for if_clause in generator.ifs:
                states.append(self._eval(if_clause, scope))
        return propagate_states(states)

    def _eval_Await(self, node, scope):
        return self._eval(node.value, scope)

    def _eval_Yield(self, node, scope):
        return self._eval(node.value, scope) if node.value else CLEAN

    def _eval_YieldFrom(self, node, scope):
        return self._eval(node.value, scope)

    def _eval_Lambda(self, node, scope):
        return self._eval(node.body, scope)

    def _eval_NamedExpr(self, node, scope):
        state = self._eval(node.value, scope)
        self._bind_target(node.target, state, scope)
        return state

    def _eval_Call(self, node, scope):
        qualname = self._callee_qualname(node)
        basename = self._callee_basename(node)

        # 1. Explicit sanitizers clear taint unconditionally.
        if self.config.is_sanitizer(qualname, basename):
            self._eval_call_arguments(node, scope)
            return CLEAN

        # 2. Whitelist / validation functions are treated as returning a
        #    value that is safe to use at a sink.
        if self.config.is_validator(qualname, basename):
            self._eval_call_arguments(node, scope)
            return CLEAN

        # 3. Builtin input() is itself a taint source.
        if basename == "input" and self.config.is_source("input"):
            self._eval_call_arguments(node, scope)
            return TaintState(True, {"input"})

        # 4. Intra-procedural local function summaries.
        func_node = self._func_defs.get(basename)
        if func_node is not None and self._is_local_call(node, func_node):
            return self._apply_local_summary(node, func_node, scope)

        # 5. Unresolved calls: taint on any argument or receiver propagates
        #    to the result, but the result can never be claimed clean because
        #    the callee itself is not understood.
        arg_states = self._eval_call_arguments(node, scope)
        if isinstance(node.func, ast.Attribute):
            arg_states.append(self._eval(node.func.value, scope))
        origins = frozenset()
        for state in arg_states:
            if state is not None and state.tainted:
                origins |= state.origins
        if origins:
            return TaintState(True, origins)
        return None

    def _eval_call_arguments(self, node, scope):
        states = []
        for arg in node.args:
            states.append(self._eval(arg, scope))
        for keyword in node.keywords:
            states.append(self._eval(keyword.value, scope))
        return states

    def _apply_local_summary(self, node, func_node, scope):
        summary = self._ensure_func_summary(func_node)
        if summary is None:
            # No return value we could model: stay conservative.
            return None
        if not summary.tainted:
            return CLEAN

        arg_states = self._bind_call_arguments(node, func_node, scope)
        origins = frozenset()
        tainted = False
        for origin in summary.origins:
            if not origin.startswith("param:"):
                tainted = True
                origins |= {origin}
                continue
            param_name = origin[len("param:"):]
            if param_name not in arg_states:
                # Unresolved parameter (e.g. variadic/default): conservative.
                tainted = True
                origins |= {origin}
                continue
            arg_state = arg_states[param_name]
            if arg_state is None:
                tainted = True
                origins |= {origin + "(unresolved)"}
            elif arg_state.tainted:
                tainted = True
                origins |= arg_state.origins
        if not tainted:
            return CLEAN
        return TaintState(True, origins)

    def _bind_call_arguments(self, node, func_node, scope):
        arg_states = {}
        args = func_node.args
        positional = list(args.posonlyargs) + list(args.args)
        for index, arg_node in enumerate(node.args):
            state = self._eval(arg_node, scope)
            if index < len(positional):
                arg_states[positional[index].arg] = state
            elif args.vararg is not None:
                arg_states[args.vararg.arg] = propagate_states(
                    [arg_states.get(args.vararg.arg), state]
                )
        for keyword in node.keywords:
            state = self._eval(keyword.value, scope)
            if keyword.arg is None and args.kwarg is not None:
                arg_states[args.kwarg.arg] = propagate_states(
                    [arg_states.get(args.kwarg.arg), state]
                )
            elif keyword.arg is not None:
                arg_states[keyword.arg] = state
        return arg_states

    def _is_local_call(self, node, func_node):
        # Only plain name calls resolve to local defs; attribute calls and
        # shadowed imports are left to the generic argument propagation.
        if not isinstance(node.func, ast.Name):
            return False
        return node.func.id not in self.import_aliases

    # ------------------------------------------------------------------
    # Name resolution helpers
    # ------------------------------------------------------------------
    def _qualname(self, node):
        """Best-effort qualified name for an Attribute/Name expression."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            root = self.import_aliases.get(current.id, current.id)
            parts.append(root)
        else:
            return ""
        return ".".join(reversed(parts))

    def _callee_qualname(self, node):
        if isinstance(node.func, ast.Name):
            return self.import_aliases.get(node.func.id, node.func.id)
        if isinstance(node.func, ast.Attribute):
            return self._qualname(node.func)
        return ""

    def _callee_basename(self, node):
        qualname = self._callee_qualname(node)
        return qualname.rsplit(".", 1)[-1] if qualname else ""

    def _matches_source_chain(self, qualname):
        if not qualname:
            return False
        for source in self.config.sources:
            if qualname == source or qualname.startswith(source + "."):
                return True
            # Also match the unaliased tail, e.g. ``request.args.get``.
            tail = source.rsplit(".", 1)[-1]
            if qualname == tail or qualname.startswith(tail + "."):
                return True
        return False

    @staticmethod
    def _source_origin(qualname):
        origin = qualname
        for known in ("flask.request", "django.http.HttpRequest", "sys.argv"):
            if qualname == known or qualname.startswith(known + "."):
                return known
        return origin
