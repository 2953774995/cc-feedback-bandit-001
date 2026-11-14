#!/usr/bin/env python3
"""污点分析验收探针：用 bandit 的 Python API 扫描样本，逐条核对。

must_flag 组：真实污点路径，必须能扫到注入相关 issue。
no_high 组：安全路径，不得出现 HIGH severity issue。

在未修复的底座上本脚本应当失败（漏报/误报都复现），修复后才全绿。
"""
import glob
import os
import sys

from bandit.core import config as b_config
from bandit.core import manager as b_manager

HERE = os.path.dirname(os.path.abspath(__file__))

# 注入相关规则前缀：B60x 命令注入家族、B608 SQL 注入、B610/B611 django SQL
INJECTION_IDS = ("B60", "B61")


def scan(path):
    conf = b_config.BanditConfig()
    mgr = b_manager.BanditManager(conf, "file")
    mgr.discover_files([path], True)
    mgr.run_tests()
    return mgr.results


def describe(results):
    return [(i.test_id, i.severity, i.confidence) for i in results]


def check_must_flag(path):
    results = scan(path)
    hits = [i for i in results if i.test_id.startswith(INJECTION_IDS)]
    ok = len(hits) > 0
    return ok, describe(results)


def check_no_high(path):
    results = scan(path)
    highs = [i for i in results if i.severity == "HIGH"]
    ok = len(highs) == 0
    return ok, describe(results)


def run_group(title, pattern, checker):
    print("=" * 72)
    print(title)
    print("=" * 72)
    files = sorted(glob.glob(pattern))
    passed = 0
    for path in files:
        name = os.path.basename(path)
        ok, detail = checker(path)
        mark = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        print(f"[{mark}] {name}")
        print(f"       实际 issue: {detail if detail else '无'}")
    return passed, len(files)


def main():
    total_pass = 0
    total = 0

    p, n = run_group(
        "验收探针 · 第一组：真实污点路径必须报出",
        os.path.join(HERE, "samples", "must_flag", "*.py"),
        check_must_flag,
    )
    total_pass += p
    total += n

    p, n = run_group(
        "验收探针 · 第二组：安全路径不得出现 HIGH",
        os.path.join(HERE, "samples", "no_high", "*.py"),
        check_no_high,
    )
    total_pass += p
    total += n

    print("=" * 72)
    print(f"探针汇总：{total_pass}/{total} 通过")
    print("=" * 72)
    return 0 if total_pass == total else 1


if __name__ == "__main__":
    sys.exit(main())
