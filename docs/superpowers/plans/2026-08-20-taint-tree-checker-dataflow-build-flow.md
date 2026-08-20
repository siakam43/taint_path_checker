# taint-tree-checker 污点数据流构建流程化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 taint-tree-checker 4.3 重构为"污点传播数据流路线构建流程"主线（子节编号 4.3.1 调用树修复规则 / 4.3.2 追踪上限 / 4.3.3 完整性自检），明确扇出解析目标必须补入修复树落盘、上限截断后继续追踪，并用 22 回调夹具验证。

**Architecture:** 本计划修改一个提示词文件（`taint-tree-checker/SKILL.md`）并新增一个测试夹具。SKILL.md 改动分五组：4.3 引言替换为流程主线、三个子节标题编号化 + 2 处交叉引用精确化、"间接调用解析"补扇出补链落盘句、"落盘"条款明确扇出落盘、4.3.2 末尾新增"截断≠终止"；联动 9.1 收紧"无法追踪"误用、9.2 补充超限处理。夹具 `test_fixtures/fanout_limit/` 含 22 个注册回调（触发扇出 20 上限）+ 扇出后的独立分支 func_after（验证截断≠终止），以 TDD 方式先建夹具（基线漏报）→ 改 SKILL.md → 重跑验证 → 回归现有夹具。

**Tech Stack:** Markdown 提示词文件；验证方式为在 Claude Code 会话中通过 Skill 工具调用 `/taint-tree-checker`；git 提交。

**设计规格:** `docs/superpowers/specs/2026-08-20-taint-tree-checker-dataflow-build-flow-design.md`

**工作目录:** `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker`（本计划所有相对路径均以此为根）

---

## 执行约定

- 调用技能方式：使用 Skill 工具，skill 名 `taint-tree-checker`，args 为 `<project_dir> <tree_file>`，从仓库根目录发起。
- 技能会预查重：`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 已存在则跳过。重跑前必须先移走/删除旧结果文件。
- 报告中的"分析时间"每次运行不同，比对时忽略该行。
- 漏洞 ID 已预先算定（sha256 前 8 位 hex，输入 `{绝对路径}:{函数}:{行号}`）：
  - cb_19 危险行（test.c:29）：`/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/fanout_limit/test.c:cb_19:29` → **TAINT-260a7509**
  - func_after 危险行（test.c:45）：`/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/fanout_limit/test.c:func_after:45` → **TAINT-98ff1977**
- 夹具预期结果入库需 `git add -f`（.gitignore 忽略 `.ethunter_out/`）。
- 回归基准（既有夹具入库的预期漏洞 ID）：callback_fanout: `TAINT-fd593ace`、`TAINT-0f4173ae`（修复树 4 条链）；tree_test: `TAINT-661d88c5`、`TAINT-6d8cda29`；tree_repair: 与入库 repair01_result.md 一致。
- **技能缓存注意**：同一会话内 Skill 工具可能返回缓存旧版技能内容。若运行类步骤拿到的技能正文与磁盘最新版不一致（以 `grep -n "4.3.1" taint-tree-checker/SKILL.md` 是否命中为准），则在**新会话**执行运行类步骤，或按磁盘最新版规则执行分析并注明。

---

### Task 1: 创建夹具场景（test.c 与 fanout_limit01.json）

**Files:**
- Create: `test_fixtures/fanout_limit/test.c`
- Create: `test_fixtures/fanout_limit/fanout_limit01.json`

- [ ] **Step 1: 创建目录**

Run: `mkdir -p test_fixtures/fanout_limit`

- [ ] **Step 2: 写入 test.c（逐字节与下行一致，行号与 JSON 及漏洞 ID 强相关）**

文件 `test_fixtures/fanout_limit/test.c`：

```c
#include <stdint.h>

#define BUF_SIZE 64
#define CB_COUNT 22

static uint8_t g_buf[BUF_SIZE];
static void (*g_cbs[CB_COUNT])(uint32_t);   /* 回调表 */

/* 回调 cb_00..cb_17：校验完备 → 净化（上限内，逐一追踪） */
static void cb_00(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x00; }
static void cb_01(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x01; }
static void cb_02(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x02; }
static void cb_03(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x03; }
static void cb_04(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x04; }
static void cb_05(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x05; }
static void cb_06(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x06; }
static void cb_07(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x07; }
static void cb_08(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x08; }
static void cb_09(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x09; }
static void cb_10(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0A; }
static void cb_11(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0B; }
static void cb_12(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0C; }
static void cb_13(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0D; }
static void cb_14(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0E; }
static void cb_15(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0F; }
static void cb_16(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x10; }
static void cb_17(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x11; }
static void cb_18(uint32_t idx) { g_buf[0] = 0xEE; }   /* 不使用 idx → 停止传播 */
static void cb_19(uint32_t idx) { g_buf[idx] = 0x13; } /* 无校验 → 漏洞1（上限内） */
static void cb_20(uint32_t idx) { g_buf[idx] = 0x14; } /* 无校验 → 超限：仅列出，不补链、不报告 */
static void cb_21(uint32_t idx) { g_buf[idx] = 0x15; } /* 无校验 → 超限：仅列出，不补链、不报告 */

void init_reg(void)                                   /* 注册点（供间接调用解析搜索） */
{
    g_cbs[0] = cb_00; g_cbs[1] = cb_01; g_cbs[2] = cb_02; g_cbs[3] = cb_03;
    g_cbs[4] = cb_04; g_cbs[5] = cb_05; g_cbs[6] = cb_06; g_cbs[7] = cb_07;
    g_cbs[8] = cb_08; g_cbs[9] = cb_09; g_cbs[10] = cb_10; g_cbs[11] = cb_11;
    g_cbs[12] = cb_12; g_cbs[13] = cb_13; g_cbs[14] = cb_14; g_cbs[15] = cb_15;
    g_cbs[16] = cb_16; g_cbs[17] = cb_17; g_cbs[18] = cb_18; g_cbs[19] = cb_19;
    g_cbs[20] = cb_20; g_cbs[21] = cb_21;
}

void func_after(uint32_t idx)                          /* 扇出后的直接调用：无校验 → 漏洞2 */
{
    g_buf[idx] = 0xFF;
}

void func_disp(uint32_t ver, uint32_t idx)             /* 入口 */
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);                              /* 扇出分发点 */
    func_after(idx);                                  /* 扇出之外的独立分支——验证"截断≠终止" */
}
```

- [ ] **Step 3: 核对行号**

Run: `sed -n '10p;27p;28p;29p;30p;31p;33p;43p;45p;48p' test_fixtures/fanout_limit/test.c`

Expected:
```
static void cb_00(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x00; }
static void cb_17(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x11; }
static void cb_18(uint32_t idx) { g_buf[0] = 0xEE; }   /* 不使用 idx → 停止传播 */
static void cb_19(uint32_t idx) { g_buf[idx] = 0x13; } /* 无校验 → 漏洞1（上限内） */
static void cb_20(uint32_t idx) { g_buf[idx] = 0x14; } /* 无校验 → 超限：仅列出，不补链、不报告 */
static void cb_21(uint32_t idx) { g_buf[idx] = 0x15; } /* 无校验 → 超限：仅列出，不补链、不报告 */
void init_reg(void)                                   /* 注册点（供间接调用解析搜索） */
void func_after(uint32_t idx)                          /* 扇出后的直接调用：无校验 → 漏洞2 */
    g_buf[idx] = 0xFF;
void func_disp(uint32_t ver, uint32_t idx)             /* 入口 */
```

- [ ] **Step 4: 写入 fanout_limit01.json**

文件 `test_fixtures/fanout_limit/fanout_limit01.json`：

```json
{
    "func_disp$fanout_limit01": [
        [
            {"func": "func_disp", "file": "test_fixtures/fanout_limit/test.c", "begin_line": "48"}
        ]
    ]
}
```

- [ ] **Step 5: 验证 JSON 可解析**

Run: `python3 -m json.tool test_fixtures/fanout_limit/fanout_limit01.json > /dev/null && echo JSON_OK`

Expected: `JSON_OK`

- [ ] **Step 6: 提交夹具文件**

```bash
git add test_fixtures/fanout_limit/test.c test_fixtures/fanout_limit/fanout_limit01.json
git commit -m "test: add fanout_limit fixture for taint-tree-checker fanout-limit tracking"
```

---

### Task 2: 基线运行（RED，记录当前技能漏报行为）

**Files:**
- 产出（不入库）: `test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md`

- [ ] **Step 1: 用当前（未优化）技能运行**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/fanout_limit fanout_limit01.json`

- [ ] **Step 2: 记录基线结论**

Read `test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md`，记录"结论"行与关键表述，逐字记录以下证据点：

1. 是否出现"无法追踪/不可逐一确定"字样（预期出现——复现用户实测问题）。
2. 漏洞数（预期 0 或 1——漏报 cb_19 和/或 func_after）。
3. 若产出 `fanout_limit01_tree_fixed.json`，链数是否为 0 或远少于 21（预期修复树缺链）。

若基线已正确报出 2 个漏洞（TAINT-260a7509、TAINT-98ff1977）且修复树 21 条链，说明当前技能已能处理该场景，暂停并重新审视夹具设计。

- [ ] **Step 3: 保留基线报告供对比**

```bash
cp test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md /tmp/fanout_limit01_baseline_result.md
test -f test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json && cp test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json /tmp/fanout_limit01_baseline_tree.json; true
```

---

### Task 3: 修改 SKILL.md（4.3 流程化 + 扇出落盘 + 截断≠终止 + 9.1/9.2 联动）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（4.3 全节 + 4.4 一处 + 9.1 一处 + 9.2 一处）

- [ ] **Step 1: 替换 4.3 引言为流程主线**

old_string:

```
本阶段是全部分析的质量核心：数据流不完整则后续判定全部失真。以入口函数为起点，沿调用树追踪污点传播，**过程中修复调用树**，产出完整准确的污点数据流路线集合（包含污点数据在不同变量和函数间的传递过程），必须覆盖污点可达的全部代码。
```

new_string:

```
本阶段的核心任务是构造完整准确的污点传播数据流路线，这是全部分析的质量核心，数据流不完整则后续判定全部失真。

**污点传播数据流路线构建流程：**

1. 以 4.1 标记的初始污点为起点，以调用树信息为参考，按照 4.2 污点传播模式进行污点追踪，完整追踪污点数据的不同传播路线，记录每条污点传播路线中的具体函数调用点及参数、执行的条件分支、污点在变量间的传递过程等信息。最后对每一条污点传播路线执行"4.3.3 完整性自检"。最终产出完整且准确的污点传播数据流路线集合，覆盖污点可达的全部代码。
2. 在追踪污点传播数据流路线过程中，遇到调用深度过大或单个调用分发点目标过多时，按照"4.3.2 追踪上限"规则进行规模收敛。
3. 在追踪污点传播数据流路线过程中，如果调用树信息有误，按照"4.3.1 调用树修复规则"对调用树信息进行修正。
```

- [ ] **Step 2: 三个子节标题编号化（3 处 Edit）**

2a. old_string: `**调用树修复规则：**` → new_string: `**4.3.1 调用树修复规则：**`

2b. old_string: `**追踪上限（目标可确定但规模巨大时）：**` → new_string: `**4.3.2 追踪上限（目标可确定但规模巨大时）：**`

2c. old_string: `**完整性自检（本阶段结束前强制执行）**` → new_string: `**4.3.3 完整性自检（本阶段结束前强制执行）**`

- [ ] **Step 3: "间接调用解析"补句 + 引用精确化**

old_string:

```
- **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数。**目标可确定时必须继续追踪，不得以"数量众多/链路深"为由放弃**；规模超出上限时按下方"追踪上限"规则处理。仅当目标不可确定（穷尽搜索注册点/赋值点仍无果、运行时计算地址、外部模块无源码）或源码缺失时，该分支标注"无法追踪"并停止延伸，不臆造——**标注时必须在摘要写明已尝试的搜索方式**。
```

new_string:

```
- **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数。**目标可确定时必须继续追踪，不得以"数量众多/链路深"为由放弃**；规模超出上限时按"4.3.2 追踪上限"规则处理。仅当目标不可确定（穷尽搜索注册点/赋值点仍无果、运行时计算地址、外部模块无源码）或源码缺失时，该分支标注"无法追踪"并停止延伸，不臆造——**标注时必须在摘要写明已尝试的搜索方式**。**解析出的目标函数（上限内）按"调用链缺失/中断"规则补入修复树并落盘。**
```

- [ ] **Step 4: "落盘"条款明确扇出落盘**

old_string:

```
- **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。
```

new_string:

```
- **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。**扇出解析出的目标回调（上限内）与树外延伸链均属于修复内容，必须补入修复树落盘；超出上限的剩余回调不补入，仅在摘要逐条列出。**
```

- [ ] **Step 5: 交叉引用精确化（2 处 Edit）**

5a. old_string: `均须追踪至 4.3 完整性自检的终态之一` → new_string: `均须追踪至 4.3.3 完整性自检的终态之一`

5b. old_string: `按 4.3 调用链缺失/中断规则修复调用树` → new_string: `按 4.3.1 调用链缺失/中断规则修复调用树`

- [ ] **Step 6: 4.3.2 末尾新增"截断≠终止"**

old_string:

```
- 上限仅用于规模巨大时的边界收敛，**不是常规偷懒借口**：扇出 ≤20、深度 ≤10 时必须全部逐一追踪。
```

new_string:

```
- 上限仅用于规模巨大时的边界收敛，**不是常规偷懒借口**：扇出 ≤20、深度 ≤10 时必须全部逐一追踪。
- **截断≠终止**：因深度/扇出上限停止延伸的只是被截断的分支。该分支之外的污点变量、其他分支、其他链必须继续追踪，扇出/深度处理结束后分析照常进行，不得以上限为由提前结束整棵树的分析。
```

- [ ] **Step 7: 9.1 思维陷阱行收紧**

old_string:

```
| "回调太多/链路太深，标无法追踪吧" | 数量与深度不是无法追踪的理由。上限内必须完整追踪；超出上限的逐条列出（函数名+行号），不得笼统跳过 |
```

new_string:

```
| "回调太多/链路太深，标无法追踪吧" | 数量与深度不是无法追踪的理由。对**可确定**目标使用"无法追踪/不可逐一确定"标注属于违规；上限内必须完整追踪，超出上限的逐条列出（函数名+行号），不得笼统跳过 |
```

- [ ] **Step 8: 9.2 边缘情况行补充**

old_string:

```
| 间接调用扇出超出上限（深度>10 或单分发点回调>20） | 按"追踪上限"规则停止延伸，摘要逐条列出未深挖项（函数名+行号）；已追踪部分照常分析 |
```

new_string:

```
| 间接调用扇出超出上限（深度>10 或单分发点回调>20） | 按"4.3.2 追踪上限"规则停止延伸，摘要逐条列出未深挖项（函数名+行号）；超限回调不补入修复树，其余分支继续追踪，已追踪部分照常分析 |
```

- [ ] **Step 9: 确认改动**

Run: `grep -n "4\.3\.[123]\|截断≠终止\|解析出的目标函数" taint-tree-checker/SKILL.md`

Expected：4.3.1/4.3.2/4.3.3 标题各一处、引言三处引用、"截断≠终止"一处、"解析出的目标函数（上限内）"一处；无残留"按下方"追踪上限""字样（旧引用已替换）。

Run: `grep -n "按下方\|追踪至 4\.3 完整性\|按 4\.3 调用链缺失" taint-tree-checker/SKILL.md; true`

Expected：无输出。

- [ ] **Step 10: 提交 SKILL.md 改动**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: add dataflow-build flow and fanout persistence rules to taint-tree-checker 4.3"
```

---

### Task 4: 用优化后技能重跑夹具并核对（GREEN）

**Files:**
- 产出（本任务核对后，Task 5 入库）: `test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md` 与 `fanout_limit01_tree_fixed.json`

- [ ] **Step 1: 移除基线结果（技能有预查重，不删会直接跳过）**

```bash
rm -f test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json
```

- [ ] **Step 2: 重跑技能**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/fanout_limit fanout_limit01.json`

- [ ] **Step 3: 核对报告硬指标**

Read `test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md`，逐项核对：

1. 结论行 = "发现 2 个安全漏洞"。
2. 漏洞 ID 恰为 `TAINT-260a7509`（cb_19，行 29）与 `TAINT-98ff1977`（func_after，行 45），各一次。
3. 报告全文无"无法追踪"与"不可逐一确定"字样：

Run: `grep -c "无法追踪\|不可逐一确定" test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md; true`

Expected: `0`

4. 摘要中 cb_00..cb_19 逐回调一行结论（净化/停止传播/危险使用点），cb_20 与 cb_21 以"超限"逐条列出（可 grep "cb_20" 确认其在摘要出现且无对应漏洞条目）。

- [ ] **Step 4: 核对修复树**

```bash
python3 -c "import json;t=json.load(open('test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json'));print(len(t['func_disp$fanout_limit01']))"
```

Expected: `21`（func_disp → cb_00 … cb_19 共 20 条 + func_disp → func_after 1 条）。

```bash
grep -c "cb_20\|cb_21" test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json; true
```

Expected: `0`（超限回调不补链）。

**任一指标不符，进入 debugging 流程定位是 SKILL.md 文案问题还是执行问题，修复后从 Step 1 重跑。**

- [ ] **Step 5: 与基线对比**

```bash
diff <(grep -c "^### 漏洞" /tmp/fanout_limit01_baseline_result.md) <(grep -c "^### 漏洞" test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md); true
```

人工确认：新报告漏洞数（2）> 基线漏洞数（预期 0 或 1），说明优化生效。

---

### Task 5: 固化预期报告并回归现有夹具

**Files:**
- Create（入库）: `test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md`、`fanout_limit01_tree_fixed.json`
- 回归比对: `test_fixtures/callback_fanout/.ethunter_out/`、`test_fixtures/tree_test/.ethunter_out/`、`test_fixtures/tree_repair/.ethunter_out/`

- [ ] **Step 1: 入库预期报告与修复树（注意 -f）**

```bash
git add -f test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_result.md test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json
git commit -m "test: add expected report for fanout_limit fixture"
```

- [ ] **Step 2: 备份现有夹具输出**

```bash
mv test_fixtures/callback_fanout/.ethunter_out /tmp/callback_fanout_ethunter_backup
mv test_fixtures/tree_test/.ethunter_out /tmp/tree_test_ethunter_backup
mv test_fixtures/tree_repair/.ethunter_out /tmp/tree_repair_ethunter_backup
```

- [ ] **Step 3: 重跑 callback_fanout（4 回调小规模扇出——验证行为不变）**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/callback_fanout fanout01.json`

- [ ] **Step 4: 重跑 tree_test**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_test ef4ebf80.json`

- [ ] **Step 5: 重跑 tree_repair**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_repair repair01.json`

- [ ] **Step 6: 回归比对（忽略"分析时间"行）**

```bash
diff <(grep -v "分析时间" callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md) \
     <(grep -v "分析时间" /tmp/callback_fanout_ethunter_backup/taint-tree-checker/fanout01_result.md) | head -40
diff <(grep -v "分析时间" tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md) \
     <(grep -v "分析时间" /tmp/tree_test_ethunter_backup/taint-tree-checker/ef4ebf80_result.md) | head -40
diff <(grep -v "分析时间" tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md) \
     <(grep -v "分析时间" /tmp/tree_repair_ethunter_backup/taint-tree-checker/repair01_result.md) | head -40
```

Expected：三份 diff 为空或仅有极小措辞差异。核对要点：
- callback_fanout：漏洞 ID 仍为 `TAINT-fd593ace`、`TAINT-0f4173ae`；修复树仍为 4 条链（func_disp→cb_a/cb_b/cb_c→helper_write/cb_d）。
- tree_test：`TAINT-661d88c5`、`TAINT-6d8cda29`；tree_repair 与入库一致。
- 若出现新报/漏报，进入 debugging 定位：确认是 4.3 重构引起的（需修订文案）还是执行波动（重跑一次观察）。

- [ ] **Step 7: 恢复备份**

```bash
rm -rf test_fixtures/callback_fanout/.ethunter_out test_fixtures/tree_test/.ethunter_out test_fixtures/tree_repair/.ethunter_out
mv /tmp/callback_fanout_ethunter_backup test_fixtures/callback_fanout/.ethunter_out
mv /tmp/tree_test_ethunter_backup test_fixtures/tree_test/.ethunter_out
mv /tmp/tree_repair_ethunter_backup test_fixtures/tree_repair/.ethunter_out
git status --short   # 预期无改动（.ethunter_out 被忽略且已恢复原状）
```

---

### Task 6: 收尾自检

- [ ] **Step 1: 全量状态检查**

Run: `git status --short && git log --oneline -6`

Expected：工作区干净（rr1.txt/rr2.txt 为既有未跟踪文件，不处理）；最近提交依次为预期报告、SKILL.md 优化、夹具三个新提交。

- [ ] **Step 2: 核对 SKILL.md 4.3 引用一致性**

Run: `grep -n "4\.3\.[123]" taint-tree-checker/SKILL.md`

人工核对清单：
- 引言三条流程各引用 4.3.1/4.3.2/4.3.3 一次
- 4.3.1 标题、4.3.2 标题、4.3.3 标题各一处
- 4.3.2"上限内必须完整追踪到终态"→ 4.3.3 完整性自检
- 4.4"树外函数追踪"→ 4.3.1 调用链缺失/中断规则
- 9.2 超限行 → 4.3.2 追踪上限
- 第三章第 4 条与 4.3.3 自检内残留的"4.3"整节引用（如"按 4.3 决定是否补入"）保持整节引用即可，不必编号化

- [ ] **Step 3: 完成**

计划结束。产出：SKILL.md 4.3 流程化（1 次提交）、新夹具与预期报告（2 次提交）、回归验证通过（3 个既有夹具）。
