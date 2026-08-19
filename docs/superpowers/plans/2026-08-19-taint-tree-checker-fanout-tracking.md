# taint-tree-checker 回调扇出追踪规则实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 堵住"间接调用扇出时 AI 以数量/深度为由放弃追踪"的漏洞：目标可确定时强制继续追踪，定义明确上限（深10/扇出20），收紧"无法追踪"定义，并用扇出夹具验证。

**Architecture:** 修改提示词文件 `taint-tree-checker/SKILL.md` 五处（4.3 间接调用解析行重写、4.3 新增追踪上限块、完整性自检收紧、7.3/7.4 摘要联动、9.1/9.2 补行），并新增回调扇出夹具 `test_fixtures/callback_fanout/`。TDD 顺序：先建夹具做基线（RED：确认旧技能放弃行为）→ 改 SKILL.md → 重跑验证（GREEN：2 漏洞+逐回调结论+修复树4链）→ 回归三个既有夹具。

**Tech Stack:** Markdown 提示词文件；验证方式为在 Claude Code 会话中按 SKILL.md 语义执行分析并写报告；git 提交。

**设计规格:** `docs/superpowers/specs/2026-08-19-taint-tree-checker-fanout-tracking-design.md`

**工作目录:** `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker`（本计划所有相对路径均以此为根）

---

## 执行约定

- 分析执行方式：直接按 `taint-tree-checker/SKILL.md` 当前语义对夹具执行完整分析（该技能是提示词，执行者即分析者），报告写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md`。
- 预查重：`{TreeID}_result.md` 已存在时技能会跳过——重跑前必须先删除旧结果文件。
- 漏洞 ID 已预先算定（sha256 前 8 位 hex，输入 `{绝对路径}:{函数}:{行号}`）：
  - 漏洞1 `g_buf[idx] = 0xBB`：`.../callback_fanout/test.c:cb_b:15` → **TAINT-fd593ace**
  - 漏洞2 `g_buf[idx] = 0xCC`：`.../callback_fanout/test.c:helper_write:23` → **TAINT-0f4173ae**
- 夹具预期结果入库需 `git add -f`（.gitignore 忽略 `.ethunter_out/`）。
- 报告"分析时间"每次不同，回归比对时忽略该行。

---

### Task 1: 创建扇出夹具（test.c 与 fanout01.json）

**Files:**
- Create: `test_fixtures/callback_fanout/test.c`
- Create: `test_fixtures/callback_fanout/fanout01.json`

- [ ] **Step 1: 创建目录**

Run: `mkdir -p test_fixtures/callback_fanout`

- [ ] **Step 2: 写入 test.c（逐字节与下行一致，行号与 JSON/ID 强相关）**

文件 `test_fixtures/callback_fanout/test.c`：

```c
#include <stdint.h>

#define BUF_SIZE 64
#define CB_COUNT 4

static uint8_t g_buf[BUF_SIZE];
static void (*g_cbs[CB_COUNT])(uint32_t);   /* 回调表 */

static void cb_a(uint32_t idx) {            /* 回调1：校验完备 → 不应报 */
    if (idx >= BUF_SIZE) return;
    g_buf[idx] = 0xAA;
}

static void cb_b(uint32_t idx) {            /* 回调2：无校验 → 漏洞1 */
    g_buf[idx] = 0xBB;
}

static void cb_c(uint32_t idx) {            /* 回调3：传递污点到树外 helper → 漏洞2 */
    helper_write(idx);                      /* 深一层，验证补链 */
}

static void helper_write(uint32_t idx) {    /* 树外辅助函数 */
    g_buf[idx] = 0xCC;                      /* 无校验 */
}

static void cb_d(uint32_t idx) {            /* 回调4：不使用 idx */
    g_buf[0] = 0xDD;
}

void init_reg(void) {                       /* 注册点（供间接调用解析搜索） */
    g_cbs[0] = cb_a; g_cbs[1] = cb_b;
    g_cbs[2] = cb_c; g_cbs[3] = cb_d;
}

void func_disp(uint32_t ver, uint32_t idx)  /* 入口 */
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);                    /* 间接调用扇出，输入树在此中断 */
}
```

- [ ] **Step 3: 核对行号**

Run: `sed -n '9p;14p;15p;18p;22p;23p;26p;30p;35p' test_fixtures/callback_fanout/test.c`

Expected:
```
static void cb_a(uint32_t idx) {            /* 回调1：校验完备 → 不应报 */
static void cb_b(uint32_t idx) {            /* 回调2：无校验 → 漏洞1 */
    g_buf[idx] = 0xBB;
static void cb_c(uint32_t idx) {            /* 回调3：传递污点到树外 helper → 漏洞2 */
static void helper_write(uint32_t idx) {    /* 树外辅助函数 */
    g_buf[idx] = 0xCC;                      /* 无校验 */
static void cb_d(uint32_t idx) {            /* 回调4：不使用 idx */
void init_reg(void) {                       /* 注册点（供间接调用解析搜索） */
void func_disp(uint32_t ver, uint32_t idx)  /* 入口 */
```

- [ ] **Step 4: 写入 fanout01.json（单链、仅入口节点）**

文件 `test_fixtures/callback_fanout/fanout01.json`：

```json
{
    "func_disp$fanout01": [
        [
            {"func": "func_disp", "file": "test_fixtures/callback_fanout/test.c", "begin_line": "35"}
        ]
    ]
}
```

- [ ] **Step 5: 验证 JSON 可解析**

Run: `python3 -m json.tool test_fixtures/callback_fanout/fanout01.json > /dev/null && echo JSON_OK`

Expected: `JSON_OK`

- [ ] **Step 6: 提交夹具文件**

```bash
git add test_fixtures/callback_fanout/test.c test_fixtures/callback_fanout/fanout01.json
git commit -m "test: add callback_fanout fixture for taint-tree-checker indirect-call tracking"
```

---

### Task 2: 基线运行（RED：确认旧技能放弃行为）

**Files:**
- 产出（不入库）: `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`

- [ ] **Step 1: 创建输出目录**

Run: `mkdir -p test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker`

- [ ] **Step 2: 按当前 SKILL.md 语义执行基线分析**

以 `test_fixtures/callback_fanout` 为 project_dir、`fanout01.json` 为 tree_file，按当前（未修改）SKILL.md 完整执行：解析 JSON → 读 test.c → 初始污点（ver、idx）→ 4.3 间接调用解析与修复 → 第五章校验检查 → 报告。报告写入 `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`。

- [ ] **Step 3: 记录基线证据**

Read 基线报告，记录三项：
1. 结论行漏洞数（预期 0 或 1——旧技能易在扇出处停止延伸）。
2. 摘要中是否出现"无法逐一追踪/链路过深/数量众多"等放弃表述（**逐字摘录**）。
3. 是否漏列部分回调（cb_a/cb_b/cb_c/cb_d/helper_write 各函数名在报告中出现情况）。

判定分支：若基线**出现放弃表述或漏报**（预期情况）→ RED 成立，继续 Task 3。若基线意外完整报出 2 个漏洞且逐回调结论齐全 → 夹具未复现放弃行为，**暂停并汇报**，规则修改仍作为防回归约束继续（不阻塞）。

- [ ] **Step 4: 保留基线报告供对比**

Run: `cp test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md /tmp/fanout01_baseline_result.md`

---

### Task 3: 4.3 "间接调用解析"行重写

**Files:**
- Modify: `taint-tree-checker/SKILL.md:195`

- [ ] **Step 1: 替换该行**

old_string:

```
- **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数；无法确定目标时该分支标注"无法追踪"并停止延伸，不臆造。
```

new_string:

```
- **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数。**目标可确定时必须继续追踪，不得以"数量众多/链路深"为由放弃**；规模超出上限时按下方"追踪上限"规则处理。仅当目标不可确定（穷尽搜索注册点/赋值点仍无果、运行时计算地址、外部模块无源码）或源码缺失时，该分支标注"无法追踪"并停止延伸，不臆造——**标注时必须在摘要写明已尝试的搜索方式**。
```

- [ ] **Step 2: 确认改动**

Run: `grep -n "不得以" taint-tree-checker/SKILL.md`

Expected: 命中第 195 行。

---

### Task 4: 4.3 新增"追踪上限"规则块

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（"落盘"条目之后、"完整性自检"之前插入）

- [ ] **Step 1: 插入规则块**

old_string（以"落盘"行+完整性自检行夹逼定位）:

```
- **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。

**完整性自检（本阶段结束前强制执行）**
```

new_string:

```
- **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。

**追踪上限（目标可确定但规模巨大时）：**

- **深度上限**：自入口函数起（入口为第 1 层），单条链最长追踪 10 层调用。第 10 层仍继续传播时停止延伸，摘要逐条列出链尾函数（函数名+行号+继续传播去向）。
- **扇出上限**：单个分发点（函数表/注册回调集）最多追踪 20 个目标回调，按注册/初始化/表项顺序取前 20 个完整追踪；其余回调在摘要逐条列出（函数名+行号）。**每个分发点独立计算上限**（各自 20 个）。
- **上限内必须完整追踪到终态**：上限之内的每个回调/分支，均须追踪至 4.3 完整性自检的终态之一（停止传播/无害消费/净化/危险使用点），不得中途以"复杂"为由跳过。
- 上限仅用于规模巨大时的边界收敛，**不是常规偷懒借口**：扇出 ≤20、深度 ≤10 时必须全部逐一追踪。

**完整性自检（本阶段结束前强制执行）**
```

- [ ] **Step 2: 确认改动**

Run: `grep -n "追踪上限\|扇出上限\|深度上限" taint-tree-checker/SKILL.md`

Expected: 各命中一次，位于 4.3 节内（"落盘"之后）。

---

### Task 5: 完整性自检收紧"无法追踪"定义

**Files:**
- Modify: `taint-tree-checker/SKILL.md:198`（"落盘"块之后的完整性自检段）

- [ ] **Step 1: 替换该句**

old_string:

```
标注"无法追踪"（间接调用目标不明或源码缺失，记录于摘要）
```

new_string:

```
标注"无法追踪"（**仅限两类**：间接调用目标不可确定且已写明搜索方式；源码缺失。**"数量众多/链路深"不属于无法追踪**，规模超上限的按"追踪上限"规则在摘要逐条列出）
```

- [ ] **Step 2: 确认改动**

Run: `grep -n "仅限两类" taint-tree-checker/SKILL.md`

Expected: 命中一次。

---

### Task 6: 报告摘要联动（7.3 / 7.4）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（7.3 分析摘要说明句、7.4 分析情况说明句）

- [ ] **Step 1: 7.3 无漏洞模板摘要句**

old_string:

```
（简述调用树功能、调用树修复情况——补充/延伸了哪些链或"未修复"、污点数据追踪结果、关键校验点说明）
```

new_string:

```
（简述调用树功能、调用树修复情况——补充/延伸了哪些链或"未修复"、污点数据追踪结果、关键校验点说明。存在间接调用扇出时，摘要必须**逐回调/逐分支给出一行结论**（函数名：是否接收污点；追踪至何终态），禁止以"无法逐一追踪"等笼统表述代替。）
```

- [ ] **Step 2: 7.4 有漏洞模板分析情况句**

old_string:

```
（调用树共含 M 条链；各链覆盖结论：已纳入数据流追踪/跳过及原因；调用树修复情况：补充/延伸了哪些链或"未修复"）
```

new_string:

```
（调用树共含 M 条链；各链覆盖结论：已纳入数据流追踪/跳过及原因；调用树修复情况：补充/延伸了哪些链或"未修复"。存在间接调用扇出时，必须**逐回调/逐分支给出一行结论**（函数名：是否接收污点；追踪至何终态），禁止以"无法逐一追踪"等笼统表述代替。）
```

- [ ] **Step 3: 确认改动**

Run: `grep -n "逐回调/逐分支" taint-tree-checker/SKILL.md`

Expected: 命中两处（7.3 与 7.4）。

---

### Task 7: 9.1 陷阱行 + 9.2 边缘情况行

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（9.1 表尾、9.2 表尾）

- [ ] **Step 1: 9.1 表尾追加陷阱行**

old_string（当前 9.1 表最后一行）:

```
| "这里已经有 if 校验了，所以安全" | 存在校验≠校验有效。仍按 5.3 检查校验是否完备、是否可被绕过（整数回绕、符号性错配、校验对象错位等）；须能给出具体绕过输入才可推翻 |
```

new_string:

```
| "这里已经有 if 校验了，所以安全" | 存在校验≠校验有效。仍按 5.3 检查校验是否完备、是否可被绕过（整数回绕、符号性错配、校验对象错位等）；须能给出具体绕过输入才可推翻 |
| "回调太多/链路太深，标无法追踪吧" | 数量与深度不是无法追踪的理由。上限内必须完整追踪；超出上限的逐条列出（函数名+行号），不得笼统跳过 |
```

- [ ] **Step 2: 9.2 表尾追加边缘情况行**

old_string（当前 9.2 表最后一行）:

```
| 分析不完整但无确认漏洞 | 使用无漏洞报告模板，在摘要中说明各链分析范围及中断原因。未确认的漏洞不报告 |
```

new_string:

```
| 分析不完整但无确认漏洞 | 使用无漏洞报告模板，在摘要中说明各链分析范围及中断原因。未确认的漏洞不报告 |
| 间接调用扇出超出上限（深度>10 或单分发点回调>20） | 按"追踪上限"规则停止延伸，摘要逐条列出未深挖项（函数名+行号）；已追踪部分照常分析 |
```

- [ ] **Step 3: 确认改动**

Run: `grep -n "回调太多\|扇出超出上限" taint-tree-checker/SKILL.md`

Expected: 各命中一次。

- [ ] **Step 4: 提交 SKILL.md 全部改动**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: add fanout tracking limits and forbid giving up on indirect calls"
```

---

### Task 8: 重跑夹具并核对（GREEN）

**Files:**
- 产出（核对后 Task 9 入库）: `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`
- 产出: `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_tree_fixed.json`

- [ ] **Step 1: 删除基线结果（预查重会跳过）**

Run: `rm test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`

- [ ] **Step 2: 按修改后 SKILL.md 语义重新执行完整分析**

同 Task 2 Step 2 的流程，但按新语义：枚举 `init_reg` 注册点确定 4 个回调目标；逐回调追踪至终态；cb_c 的树外调用 `helper_write` 按 4.3 补链；产出报告与 `fanout01_tree_fixed.json`。

- [ ] **Step 3: 核对报告硬指标**

Read `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`，逐项核对：

1. 结论 = "发现 2 个安全漏洞"。
2. 漏洞 ID 恰为 `TAINT-fd593ace`（所在函数 cb_b、关键行号 15）与 `TAINT-0f4173ae`（所在函数 helper_write、关键行号 23），各一次，无重复。
3. 报告中**不含**"无法逐一追踪"字样。
4. 摘要中 cb_a、cb_b、cb_c、cb_d 四个回调**各有一行结论**（cb_a 校验后净化；cb_b 到达危险使用点；cb_c 树外延伸至 helper_write 到达危险使用点；cb_d 形参接收污点但未使用、停止传播）。
5. `fanout01_tree_fixed.json` 存在且含 4 条链：func_disp → cb_a；func_disp → cb_b；func_disp → cb_c → helper_write；func_disp → cb_d（begin_line 依次 35/9、35/14、35/18/22、35/26）。

**任一指标不符，进入 debugging 流程定位是规则文案问题还是执行问题，修复后从 Step 1 重跑。**

- [ ] **Step 4: 与基线对比**

Run: `diff <(grep -c "^### 漏洞" /tmp/fanout01_baseline_result.md) <(grep -c "^### 漏洞" test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md); true`

人工确认：新报告漏洞数 > 基线漏洞数（基线 ≤1，新报告 = 2），且基线中的放弃表述在新报告中消失。

---

### Task 9: 入库预期结果并回归既有夹具

**Files:**
- Create（入库）: `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md`
- Create（入库）: `test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_tree_fixed.json`
- 回归比对: `test_fixtures/insufficient_check/`、`test_fixtures/tree_test/`、`test_fixtures/tree_repair/`

- [ ] **Step 1: 入库预期文件（注意 -f）**

```bash
git add -f test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md \
        test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_tree_fixed.json
git commit -m "test: add expected report for callback_fanout fixture"
```

- [ ] **Step 2: 备份三个既有夹具输出**

```bash
mv test_fixtures/insufficient_check/.ethunter_out /tmp/insufficient_check_ethunter_backup
mv test_fixtures/tree_test/.ethunter_out /tmp/tree_test_ethunter_backup
mv test_fixtures/tree_repair/.ethunter_out /tmp/tree_repair_ethunter_backup
```

- [ ] **Step 3: 重跑 insufficient_check**

以 `test_fixtures/insufficient_check` 为 project_dir、`bypass01.json` 为 tree_file 执行分析。

Expected: 结论 2 个漏洞，ID 集合 = {TAINT-8ee72c47, TAINT-ba4f59e4}，FUNC3 不报漏洞。

- [ ] **Step 4: 重跑 tree_test**

以 `test_fixtures/tree_test` 为 project_dir、`ef4ebf80.json` 为 tree_file 执行分析。

Expected: 结论 2 个漏洞，ID 集合 = {TAINT-661d88c5, TAINT-6d8cda29}。

- [ ] **Step 5: 重跑 tree_repair**

以 `test_fixtures/tree_repair` 为 project_dir、`repair01.json` 为 tree_file 执行分析。

Expected: 结论 1 个漏洞，ID = TAINT-4d15b5b2；`repair01_tree_fixed.json` 与备份逐字节一致。

- [ ] **Step 6: 回归比对（忽略"分析时间"行）**

```bash
diff <(grep -v "分析时间" test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md) \
     <(grep -v "分析时间" /tmp/insufficient_check_ethunter_backup/taint-tree-checker/bypass01_result.md) | head -30
diff <(grep -v "分析时间" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md) \
     <(grep -v "分析时间" /tmp/tree_test_ethunter_backup/taint-tree-checker/ef4ebf80_result.md) | head -30
diff <(grep -v "分析时间" test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md) \
     <(grep -v "分析时间" /tmp/tree_repair_ethunter_backup/taint-tree-checker/repair01_result.md) | head -30
diff test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_tree_fixed.json \
     /tmp/tree_repair_ethunter_backup/taint-tree-checker/repair01_tree_fixed.json && echo TREE_FIXED_IDENTICAL
```

Expected：各 diff 为空或仅有措辞级差异；**漏洞 ID 集合与判定不得变化**；`TREE_FIXED_IDENTICAL`。若出现新报/漏报，进入 debugging 定位：确认是新规则引起误报（需修订文案）还是执行波动（重跑观察）。

- [ ] **Step 7: 恢复备份**

```bash
rm -rf test_fixtures/insufficient_check/.ethunter_out test_fixtures/tree_test/.ethunter_out test_fixtures/tree_repair/.ethunter_out
mv /tmp/insufficient_check_ethunter_backup test_fixtures/insufficient_check/.ethunter_out
mv /tmp/tree_test_ethunter_backup test_fixtures/tree_test/.ethunter_out
mv /tmp/tree_repair_ethunter_backup test_fixtures/tree_repair/.ethunter_out
git status --short   # 预期仅剩 rr1.txt/rr2.txt（既有未跟踪文件）
```

---

### Task 10: 收尾自检

- [ ] **Step 1: 全量一致性检查**

Run: `git status --short && git diff HEAD -- taint-tree-checker/SKILL.md | head -5 && grep -n "追踪上限\|仅限两类\|逐回调/逐分支\|回调太多\|扇出超出上限" taint-tree-checker/SKILL.md`

Expected：工作区干净；五处新规则各就位（4.3×3、7.3/7.4、9.1、9.2）。

- [ ] **Step 2: 检查残留旧措辞**

Run: `grep -n "无法确定目标时该分支标注" taint-tree-checker/SKILL.md; true`

Expected：无输出（旧行已被重写）。

- [ ] **Step 3: 完成**

计划结束。产出：SKILL.md 扇出追踪规则（1 次提交）、新夹具与预期结果（2 次提交）、回归验证通过。
