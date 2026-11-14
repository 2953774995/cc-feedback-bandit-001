#
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the intra-procedural taint analysis."""
import ast
import textwrap

import testtools

from bandit.core import taint


def parse(code):
    return ast.parse(textwrap.dedent(code))


def analyze(code, config=None):
    return taint.TaintAnalysis(parse(code), taint.TaintConfig(config))


def first_call(tree, name=None):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if name is None:
                return node
            func = node.func
            called = getattr(func, "attr", None) or getattr(func, "id", None)
            if called == name:
                return node
    raise AssertionError(f"no call named {name!r} found")


def find_node(tree, node_type):
    return next(
        node for node in ast.walk(tree) if isinstance(node, node_type)
    )


def load_nodes(tree, identifier):
    """Name/Attribute nodes that read (not store) ``identifier``."""
    nodes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == identifier:
            if isinstance(node.ctx, ast.Load):
                nodes.append(node)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == identifier
            and isinstance(node.ctx, ast.Load)
        ):
            nodes.append(node)
    return nodes


class TaintConfigTests(testtools.TestCase):
    def test_defaults_present(self):
        conf = taint.TaintConfig.default()
        self.assertIn("flask.request", conf.sources)
        self.assertIn("sys.argv", conf.sources)
        self.assertIn("input", conf.sources)
        self.assertIn("shlex.quote", conf.sanitizers)
        self.assertIn("allow", conf.validators)

    def test_user_config_merges_and_overrides(self):
        conf = taint.TaintConfig(
            {"sources": ["myapp.request"], "sanitizers": ["myapp.clean"]}
        )
        self.assertEqual(conf.sources, ["myapp.request"])
        self.assertEqual(conf.sanitizers, ["myapp.clean"])
        # untouched key keeps defaults
        self.assertIn("allow", conf.validators)

    def test_pattern_matching(self):
        conf = taint.TaintConfig.default()
        self.assertTrue(conf.is_validator("allow"))
        self.assertTrue(conf.is_validator("mymod.validate_user"))
        self.assertFalse(conf.is_validator("render"))
        self.assertTrue(conf.is_sanitizer("shlex.quote"))
        self.assertTrue(conf.is_source("request.args"))


class SourceTests(testtools.TestCase):
    def test_flask_request_chain_is_tainted(self):
        analysis = analyze(
            """
            from flask import request
            x = request.args.get("id")
            """
        )
        call = first_call(analysis.tree, "get")
        self.assertTrue(analysis.is_tainted(call))

    def test_django_request_get_is_tainted(self):
        analysis = analyze(
            """
            def view(request):
                x = request.GET.get("id")
            """
        )
        call = first_call(analysis.tree, "get")
        self.assertTrue(analysis.is_tainted(call))

    def test_sys_argv_is_tainted(self):
        analysis = analyze("x = sys.argv[1]")
        sub = next(
            node
            for node in ast.walk(analysis.tree)
            if isinstance(node, ast.Subscript)
        )
        self.assertTrue(analysis.is_tainted(sub))

    def test_input_is_tainted(self):
        analysis = analyze('x = input("prompt: ")')
        call = first_call(analysis.tree, "input")
        self.assertTrue(analysis.is_tainted(call))

    def test_constant_is_clean(self):
        analysis = analyze('x = "ls -l"')
        constant = find_node(analysis.tree, ast.Constant)
        self.assertTrue(analysis.is_clean(constant))


class PropagationTests(testtools.TestCase):
    def test_multi_hop_assignment(self):
        analysis = analyze(
            """
            from flask import request
            raw = request.args.get("id")
            q = raw
            p = q
            """
        )
        # The load of q inside ``p = q`` must still carry the source taint.
        name_q = load_nodes(analysis.tree, "q")[0]
        self.assertTrue(analysis.is_tainted(name_q))

    def test_container_propagation(self):
        analysis = analyze(
            """
            import sys
            args = {"cmd": sys.argv[1]}
            parts = [args["cmd"], "-l"]
            """
        )
        list_node = find_node(analysis.tree, ast.List)
        self.assertTrue(analysis.is_tainted(list_node))

    def test_attribute_propagation(self):
        analysis = analyze(
            """
            from flask import request
            class Box:
                pass
            box = Box()
            box.cmd = request.args.get("cmd")
            x = box.cmd
            """
        )
        attr = next(
            node
            for node in load_nodes(analysis.tree, "cmd")
            if isinstance(node, ast.Attribute)
        )
        self.assertTrue(analysis.is_tainted(attr))

    def test_string_operations_propagate(self):
        analysis = analyze(
            """
            from flask import request
            raw = request.args.get("x")
            a = "a" + raw
            b = "b %s" % raw
            c = "c {}".format(raw)
            d = f"d {raw}"
            """
        )
        tainted_binop = [
            node
            for node in ast.walk(analysis.tree)
            if isinstance(node, ast.BinOp)
            and analysis.is_tainted(node)
        ]
        self.assertEqual(2, len(tainted_binop))  # + and %
        joined = find_node(analysis.tree, ast.JoinedStr)
        self.assertTrue(analysis.is_tainted(joined))
        format_call = first_call(analysis.tree, "format")
        self.assertTrue(analysis.is_tainted(format_call))

    def test_constant_reassignment_clears_taint(self):
        analysis = analyze(
            """
            from flask import request
            user_cmd = request.args.get("cmd")
            cmd = "ls -l"
            used = cmd
            """
        )
        # Name load of cmd after reassignment must be clean
        loads = load_nodes(analysis.tree, "cmd")
        self.assertTrue(loads)
        self.assertTrue(all(analysis.is_clean(node) for node in loads))
        self.assertFalse(any(analysis.is_tainted(node) for node in loads))

    def test_unknown_origin_stays_unknown(self):
        analysis = analyze(
            """
            y = mystery(x)
            """
        )
        call = first_call(analysis.tree, "mystery")
        self.assertIsNone(analysis.get_state(call))

    def test_unknown_operand_keeps_expression_unknown(self):
        analysis = analyze(
            """
            command = "/bin/ls" + unknown_function()
            """
        )
        binop = find_node(analysis.tree, ast.BinOp)
        self.assertIsNone(analysis.get_state(binop))


class ControlFlowTests(testtools.TestCase):
    def test_branch_merge_is_conservative(self):
        analysis = analyze(
            """
            from flask import request
            def view(flag):
                cmd = request.args.get("cmd")
                if flag:
                    cmd = "ls"
                return cmd
            """
        )
        returns = [
            node
            for node in ast.walk(analysis.tree)
            if isinstance(node, ast.Return)
        ]
        self.assertEqual(1, len(returns))
        self.assertTrue(analysis.is_tainted(returns[0].value))

    def test_both_branches_clean(self):
        analysis = analyze(
            """
            def view(flag):
                if flag:
                    cmd = "ls"
                else:
                    cmd = "pwd"
                return cmd
            """
        )
        ret = find_node(analysis.tree, ast.Return)
        self.assertTrue(analysis.is_clean(ret.value))


class FunctionSummaryTests(testtools.TestCase):
    def test_parameter_to_return_propagation(self):
        analysis = analyze(
            """
            import os
            def wrap(x):
                y = x
                return y
            def main(p):
                os.system(wrap(p))
            """
        )
        call = first_call(analysis.tree, "wrap")
        # p is an unbound parameter -> symbolic taint flows through wrap
        self.assertTrue(analysis.is_tainted(call))

    def test_forward_reference_resolved(self):
        analysis = analyze(
            """
            import os
            def main(p):
                os.system(wrap(p))
            def wrap(x):
                return x
            """
        )
        call = first_call(analysis.tree, "wrap")
        self.assertTrue(analysis.is_tainted(call))

    def test_validator_clears_taint(self):
        analysis = analyze(
            """
            from flask import request
            ALLOWED = {"ls"}
            def allow(cmd):
                return cmd if cmd in ALLOWED else "date"
            cmd = allow(request.args.get("cmd"))
            """
        )
        call = first_call(analysis.tree, "allow")
        self.assertTrue(analysis.is_clean(call))

    def test_sanitizer_clears_taint(self):
        analysis = analyze(
            """
            import sys
            import shlex
            safe = shlex.quote(sys.argv[1])
            """
        )
        call = first_call(analysis.tree, "quote")
        self.assertTrue(analysis.is_clean(call))

    def test_recursion_does_not_crash(self):
        analysis = analyze(
            """
            def build(x):
                return build(x)
            y = build("z")
            """
        )
        outer = [
            node
            for node in ast.walk(analysis.tree)
            if isinstance(node, ast.Call)
        ]
        # unresolved recursive result is unknown, never an exception
        self.assertTrue(outer)
        for node in outer:
            self.assertIsNone(analysis.get_state(node))


class ParameterizedQueryTests(testtools.TestCase):
    def _execute_call(self, code):
        analysis = analyze(code)
        return first_call(analysis.tree, "execute"), analysis

    def test_parameterized_positional(self):
        call, analysis = self._execute_call(
            """
            def f(cur, name):
                cur.execute("SELECT * FROM t WHERE id = ?", (name,))
            """
        )
        self.assertTrue(analysis.is_parameterized_execute(call))

    def test_parameterized_keyword(self):
        call, analysis = self._execute_call(
            """
            def f(cur, name):
                cur.execute("SELECT * FROM t WHERE id = ?", params=(name,))
            """
        )
        self.assertTrue(analysis.is_parameterized_execute(call))

    def test_dynamic_query_is_not_parameterized(self):
        call, analysis = self._execute_call(
            """
            def f(cur, q):
                cur.execute(q, (1,))
            """
        )
        # q has unknown origin so the query text cannot be proven safe
        self.assertFalse(analysis.is_parameterized_execute(call))

    def test_executemany_recognized(self):
        analysis = analyze(
            """
            def f(cur, rows):
                cur.executemany("INSERT INTO t VALUES (?)", rows)
            """
        )
        call = first_call(analysis.tree, "executemany")
        self.assertTrue(analysis.is_parameterized_execute(call))
