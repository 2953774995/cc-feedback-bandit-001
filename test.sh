#!/bin/bash
# 验收脚本：全量回归 + 污点分析探针，分块输出，结尾汇总。
# 在仓库根目录运行：./test.sh
cd "$(dirname "$0")"
PY=.venv/bin/python
export PATH="$PWD/.venv/bin:$PATH"

echo ""
echo "############################################################"
echo "# 第一块：全量回归测试（pytest tests/，基线 274 passed）"
echo "############################################################"
"$PY" -m pytest tests/ -v
REG_RC=$?

echo ""
echo "############################################################"
echo "# 第二块：污点分析验收探针（must_flag 必报 / no_high 无 HIGH）"
echo "############################################################"
"$PY" probes/run_probes.py
PROBE_RC=$?

echo ""
echo "############################################################"
echo "# 汇总"
echo "############################################################"
if [ "$REG_RC" -eq 0 ]; then
    echo "全量回归：PASS"
else
    echo "全量回归：FAIL（退出码 $REG_RC）"
fi
if [ "$PROBE_RC" -eq 0 ]; then
    echo "验收探针：PASS（11/11）"
else
    echo "验收探针：FAIL（存在未通过项，退出码 $PROBE_RC）"
fi
echo ""
if [ "$REG_RC" -eq 0 ] && [ "$PROBE_RC" -eq 0 ]; then
    echo "总体结果：全部通过"
    exit 0
fi
echo "总体结果：存在失败项"
exit 1
