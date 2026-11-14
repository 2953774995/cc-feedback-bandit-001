#
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for taint-analysis driven injection detection.

These tests drive the full bandit pipeline (manager + visitor + plugins)
against in-memory snippets and assert on the resulting issues, covering both
the previously missed taint paths and the previously mis-flagged safe paths.
"""
import os
import tempfile
import textwrap

import testtools

from bandit.core import config as b_config
from bandit.core import manager as b_manager

INJECTION_PREFIXES = ("B60", "B61")
TAINT_MARKER = "taint"


def scan(code, config_text=None):
    if config_text is None:
        conf = b_config.BanditConfig()
    else:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False
        ) as config_file:
            config_file.write(textwrap.dedent(config_text))
            config_path = config_file.name
        try:
            conf = b_config.BanditConfig(config_path)
        finally:
            os.unlink(config_path)
    mgr = b_manager.BanditManager(conf, "file")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".py", delete=False
    ) as handle:
        handle.write(textwrap.dedent(code))
        path = handle.name
    try:
        mgr.discover_files([path], True)
        mgr.run_tests()
    finally:
        os.unlink(path)
    return mgr.results


class TaintMustFlagTests(testtools.TestCase):
    """Real taint paths that the literal-only heuristics used to miss."""

    def _injection_issues(self, code):
        return [
            issue
            for issue in scan(code)
            if issue.test_id.startswith(INJECTION_PREFIXES)
        ]

    def test_flask_request_flows_into_execute(self):
        issues = self._injection_issues(
            """
            from flask import request
            import sqlite3

            def view():
                raw = request.args.get("id")
                q = raw
                conn = sqlite3.connect("app.db")
                conn.cursor().execute(q)
            """
        )
        self.assertTrue(issues)
        self.assertEqual("B608", issues[0].test_id)
        self.assertIn(TAINT_MARKER, issues[0].text.lower())

    def test_parameter_flows_into_execute(self):
        issues = self._injection_issues(
            """
            import sqlite3

            def lookup(db_path, name):
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cond = name
                cur.execute(cond)
            """
        )
        self.assertTrue(any(i.test_id == "B608" for i in issues))

    def test_django_request_flows_into_execute(self):
        issues = self._injection_issues(
            """
            import sqlite3

            def my_view(request):
                raw = request.GET.get("id")
                q = raw
                conn = sqlite3.connect("app.db")
                conn.cursor().execute(q)
            """
        )
        self.assertTrue(any(i.test_id == "B608" for i in issues))

    def test_multi_hop_shell_taint_confirmed(self):
        issues = self._injection_issues(
            """
            from flask import request
            import subprocess

            def view():
                raw = request.form.get("cmd")
                cmd = raw
                picked = cmd
                subprocess.run(picked, shell=True)
            """
        )
        b602 = [i for i in issues if i.test_id == "B602"]
        self.assertEqual(1, len(b602))
        self.assertEqual("HIGH", b602[0].severity)
        self.assertIn(TAINT_MARKER, b602[0].text.lower())

    def test_container_shell_taint(self):
        issues = self._injection_issues(
            """
            import sys
            import subprocess

            def main():
                args = {"cmd": sys.argv[1]}
                parts = [args["cmd"], "-l"]
                subprocess.Popen(parts, shell=True)
            """
        )
        self.assertTrue(
            any(i.test_id == "B602" and i.severity == "HIGH" for i in issues)
        )

    def test_input_flows_to_os_system(self):
        issues = self._injection_issues(
            """
            import os

            def main():
                user_value = input("run: ")
                os.system(user_value)
            """
        )
        b605 = [i for i in issues if i.test_id == "B605"]
        self.assertEqual(1, len(b605))
        self.assertEqual("HIGH", b605[0].severity)
        self.assertIn(TAINT_MARKER, b605[0].text.lower())

    def test_string_concatenation_keeps_taint(self):
        issues = self._injection_issues(
            """
            from flask import request
            import subprocess

            def view():
                raw = request.args.get("x")
                subprocess.run("ls " + raw, shell=True)
            """
        )
        self.assertTrue(
            any(i.test_id == "B602" and i.severity == "HIGH" for i in issues)
        )


class TaintNoHighTests(testtools.TestCase):
    """Safe paths that must never produce a HIGH severity issue."""

    def _high_issues(self, code):
        return [issue for issue in scan(code) if issue.severity == "HIGH"]

    def test_internal_constant(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                import subprocess

                def listing():
                    command = "ls -l /tmp"
                    subprocess.run(command, shell=True)
                """
            ),
        )

    def test_shlex_quote_sanitizer(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                import shlex
                import sys
                import subprocess

                def main():
                    safe_cmd = shlex.quote(sys.argv[1])
                    subprocess.run(safe_cmd, shell=True)
                """
            ),
        )

    def test_whitelist_validator(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                from flask import request
                import subprocess

                ALLOWED = {"ls", "whoami", "date"}

                def allow(cmd):
                    if cmd in ALLOWED:
                        return cmd
                    return "date"

                def view():
                    user_cmd = request.args.get("cmd")
                    cmd = allow(user_cmd)
                    subprocess.run(cmd, shell=True)
                """
            ),
        )

    def test_constant_reassignment_overwrites_taint(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                from flask import request
                import subprocess

                def view():
                    user_cmd = request.args.get("cmd")
                    cmd = "ls -l"
                    subprocess.run(cmd, shell=True)
                """
            ),
        )

    def test_parameterized_query_not_flagged(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                import sqlite3

                def lookup(db_path, name):
                    conn = sqlite3.connect(db_path)
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT * FROM t WHERE id = ?", (name,)
                    )
                """
            ),
        )

    def test_inline_sanitizer_call(self):
        self.assertEqual(
            [],
            self._high_issues(
                """
                import shlex
                import sys
                import subprocess

                def main():
                    subprocess.run(
                        shlex.quote(sys.argv[1]), shell=True
                    )
                """
            ),
        )

    def test_computed_constant_string_keeps_legacy_high(self):
        # All-constant formatting still matches bandit's traditional
        # "computed string" heuristic rather than being silently cleared.
        issues = scan(
            """
            import subprocess

            def f():
                subprocess.Popen(
                    "/bin/ls %s" % ("x",), shell=True
                )
            """
        )
        b602 = [i for i in issues if i.test_id == "B602"]
        self.assertEqual(1, len(b602))
        self.assertEqual("HIGH", b602[0].severity)


class TaintConservatismTests(testtools.TestCase):
    """When the origin cannot be resolved, old heuristics must remain."""

    def test_unresolved_argument_keeps_traditional_high(self):
        # The value comes from an unknown function call, so taint analysis
        # makes no claim and the literal-based heuristic stays in force.
        issues = scan(
            """
            import subprocess

            def f():
                command = mystery()
                subprocess.run(command, shell=True)
            """
        )
        b602 = [i for i in issues if i.test_id == "B602"]
        self.assertEqual(1, len(b602))
        self.assertEqual("HIGH", b602[0].severity)
        # Not a taint-confirmed finding: it is the legacy heuristic verdict.
        self.assertNotIn(TAINT_MARKER, b602[0].text.lower())

    def test_function_parameter_is_symbolically_tainted(self):
        # Parameters are treated as symbolic taint sources so that taint
        # flowing through helper functions is still caught at the sink.
        issues = scan(
            """
            import subprocess

            def f(x):
                subprocess.run(x, shell=True)
            """
        )
        b602 = [i for i in issues if i.test_id == "B602"]
        self.assertEqual(1, len(b602))
        self.assertEqual("HIGH", b602[0].severity)
        self.assertIn(TAINT_MARKER, b602[0].text.lower())

    def test_unknown_function_call_is_not_claimed_clean(self):
        issues = scan(
            """
            import subprocess

            def f():
                command = "/bin/ls" + unknown_function()
                subprocess.Popen(command, shell=True)
            """
        )
        b602 = [i for i in issues if i.test_id == "B602"]
        self.assertEqual(1, len(b602))
        self.assertEqual("HIGH", b602[0].severity)


class TaintConfigIntegrationTests(testtools.TestCase):
    """Configured sources/sanitizers must take effect end to end."""

    def test_custom_sanitizer_clears_taint(self):
        config = """
            taint_analysis:
              sources:
                - flask.request
              sanitizers:
                - myclean
              validators:
                - allow
        """
        issues = scan(
            """
            from flask import request
            import subprocess

            def view():
                cmd = myclean(request.args.get("cmd"))
                subprocess.run(cmd, shell=True)
            """,
            config_text=config,
        )
        highs = [i for i in issues if i.severity == "HIGH"]
        self.assertEqual([], highs)

    def test_custom_source_is_detected(self):
        config = """
            taint_analysis:
              sources:
                - myframework.req
              sanitizers:
                - shlex.quote
              validators:
                - allow
        """
        issues = scan(
            """
            from myframework import req
            import os

            def view():
                os.system(req.value)
            """,
            config_text=config,
        )
        b605 = [i for i in issues if i.test_id == "B605"]
        self.assertEqual(1, len(b605))
        self.assertEqual("HIGH", b605[0].severity)
        self.assertIn(TAINT_MARKER, b605[0].text.lower())
