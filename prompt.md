我们在基于 bandit 做内部的 Python 代码安全门禁，现在卡在注入类检测上。bandit 现在的规则都是单节点、看字面量的启发式，没有数据流概念，导致真实的污点路径漏报，同时一批安全代码被报成高危。需要在现有框架上补一套过程内（intra-procedural）污点分析，把命令注入和 SQL 注入的判定建立在真实数据流上。

先说我在当前版本（bandit 1.8.4）实测复现的问题，代码和现象都给你，不用猜：

漏报这两类现在完全扫不出来。

第一类，外部输入透传到 SQL 执行，全程没有 SQL 字面量，B608 挂在 checks("Str") 上根本不触发：

    from flask import request
    import sqlite3

    def view():
        raw = request.args.get("id")
        q = raw
        conn = sqlite3.connect("app.db")
        conn.cursor().execute(q)

跑 `bandit` 这个文件 results 是空的，一条 issue 没有。同样的问题，参数 name 直接透传进 `cur.execute(cond)` 也不报。

第二类是误报，而且和真实输入报得一模一样，没法区分。下面这几种安全写法，现在都给 B602 HIGH：

    # 内部常量，经变量传入
    command = "ls -l /tmp"
    subprocess.run(command, shell=True)

    # shlex.quote 净化过
    safe_cmd = shlex.quote(sys.argv[1])
    subprocess.run(safe_cmd, shell=True)

    # 白名单函数校验后返回
    cmd = allow(user_input)          # allow 只返回 ALLOWED 集合内的值
    subprocess.run(cmd, shell=True)

    # 变量被常量重新赋值覆盖，污点已经不存在
    user_cmd = request.args.get("cmd")
    cmd = "ls -l"
    subprocess.run(cmd, shell=True)

对比一下，真实的 `cmd = request.args.get("cmd"); subprocess.run(cmd, shell=True)` 也是 B602 HIGH。等于说真有用户输入和内部常量、净化后的路径，结论完全一样，门禁没法据此做分级。`_evaluate_shell_call` 只看第一个参数是不是 ast.Constant，经过一次赋值就一律 HIGH，这是根因。

要做的东西：

1. 新增一个过程内污点分析模块，放在 bandit/core 下，在 node_visitor 跑插件之前先对整个模块的 AST 建好分析结果，visitor 和插件能查询某个 AST 节点上的污点状态。不要靠临时在单个插件里递归找父节点凑。

2. source 至少覆盖：Flask 的 request（request.args/get/form/values/cookies 等）、Django 的 HttpRequest（GET/POST/body）、sys.argv、内置 input()。source 集合要可配置，后面我们会自己加。

3. 污点传播要处理：直接赋值和多跳赋值（a=b，b 污点则 a 污点）、list/tuple/set/dict 容器及其元素、对象属性访问、字符串拼接（+、%、format、f-string）后结果仍带污点、函数调用参数与返回值在过程内的传递。

4. sink 对齐现有的命令注入和 SQL 注入家族：subprocess 系列带 shell=True、os.system/os.popen 等 shell 调用、cursor.execute/executemany。污点到达 sink 时给出 issue，并且能在结果里体现这条数据是经污点分析确认的。

5. 污点必须能被清除，下列情况不得再报高危：shlex.quote 这类净化函数包裹、白名单/校验函数返回后（像上面的 allow）、参数化查询（execute 带占位符、参数单独传，如 execute("... WHERE id = ?", (name,))）、变量被干净常量重新赋值覆盖。净化函数和校验函数的名单也要可配置。

6. 双向验收，这是硬指标：
   - 上面第一类漏报（输入透传 execute、多跳/容器后到 sink）必须能报出来；
   - 上面四种安全写法（内部常量、shlex.quote、白名单、常量覆盖）不得报高危，参数化查询不得报；
   - 过程内分析要保守，确实追不到来源的情况按现有逻辑处理，不要为了消灭误报把真实路径也放过。

7. 现有测试一条不能少。当前 `pytest tests/` 在 venv 里是 274 passed，改完这些用例要继续通过，新能力补上对应的单元测试和端到端用例，别只写一个 happy path。

8. 不要引入需要联网、需要 docker 或重型第三方框架的依赖，保持 bandit 现在纯 Python、离线可跑的形态。改动涉及新增模块、visitor/manager 接入和现有插件调整，注意别和 stevedore 的插件加载机制冲突。

做完我会用一组探针逐条核对：每个漏报样本要能扫到对应 issue，每个安全样本要么不报、要么不高于 LOW，同时复跑全量测试比对基线。
