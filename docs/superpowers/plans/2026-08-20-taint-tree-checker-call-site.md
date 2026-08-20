# taint-tree-checker 调用点区分与第五章流程化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 taint-tree-checker 第五章重构为"分析范围确定 → 危险使用点定位 → 校验存在性检查 → 校验完备性检查 → 漏洞分析"流程主线，引入调用点区分原则（校验结论按调用点区分），解决同函数多次调用、实参不同导致的漏报，并用新夹具验证。

**Architecture:** 本计划修改一个提示词文件（`taint-tree-checker/SKILL.md`）并新增一个测试夹具。SKILL.md 第五章重排为 5.1 分析范围确定（新增调用点区分原则）、5.2 危险使用点定位（原 5.1）、5.3 校验存在性检查（原 5.2）、5.4 校验完备性检查（原 5.3）、5.5 漏洞分析（5.5.1 新增定位说明 + 5.5.2 原 5.4 排除清单移入），同步更新 6 处交叉引用并新增 9.1 思维陷阱行。夹具 `test_fixtures/multi_call_site/` 中 FUNC0 两次调用 FUNC1（调用点1已校验、调用点2未校验）+ FUNC2 对照链，以 TDD 方式先建夹具（基线漏报）→ 改 SKILL.md → 重跑验证 → 回归现有夹具。

**Tech Stack:** Markdown 提示词文件；验证方式为在 Claude Code 会话中通过 Skill 工具调用 `/taint-tree-checker`；git 提交。

**设计规格:** `docs/superpowers/specs/2026-08-20-taint-tree-checker-call-site-design.md`

**工作目录:** `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker`（本计划所有相对路径均以此为根）

---

## 执行约定

- 调用技能方式：使用 Skill 工具，skill 名 `taint-tree-checker`，args 为 `<project_dir> <tree_file>`，从仓库根目录发起。
- 技能会预查重：`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 已存在则跳过。重跑前必须先移走/删除旧结果文件。
- 报告中的"分析时间"每次运行不同，比对时忽略该行。
- 漏洞 ID 已预先算定（sha256 前 8 位 hex，输入 `{绝对路径}:{函数}:{行号}`）：
  - `g_buf[v] = 0xAA`（FUNC1 内危险行）：`/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/multi_call_site/test.c:FUNC1:17` → **TAINT-6279b391**
- 夹具预期结果入库需 `git add -f`（.gitignore 忽略 `.ethunter_out/`，沿用 tree_repair 惯例）。
- 回归基准（既有夹具入库的预期漏洞 ID）：
  - tree_test: `TAINT-661d88c5`、`TAINT-6d8cda29`
  - callback_fanout: `TAINT-fd593ace`、`TAINT-0f4173ae`
  - tree_repair / insufficient_check: 与各自入库的 `{TreeID}_result.md` 一致（insufficient_check 为 `TAINT-8ee72c47`、`TAINT-ba4f59e4`）

---

### Task 1: 创建夹具场景（test.c 与 multi01.json）

**Files:**
- Create: `test_fixtures/multi_call_site/test.c`
- Create: `test_fixtures/multi_call_site/multi01.json`

- [ ] **Step 1: 创建目录**

Run: `mkdir -p test_fixtures/multi_call_site`

- [ ] **Step 2: 写入 test.c（逐字节与下行一致，行号与 JSON 及漏洞 ID 强相关）**

文件 `test_fixtures/multi_call_site/test.c`：

```c
#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];

void FUNC0(uint32_t idx, uint32_t off)
{
    if (idx >= BUF_SIZE)      /* 校验 idx：只覆盖调用点1 */
        return;
    FUNC1(idx);               /* 调用点1：实参已校验 */
    FUNC1(off);               /* 调用点2：实参未校验 → 漏洞经此触发 */
}

void FUNC1(uint32_t v)
{
    g_buf[v] = 0xAA;          /* 危险使用点 */
}

void FUNC2(uint32_t idx, uint32_t off)  /* 对照链：两个调用点均已校验 */
{
    if (idx >= BUF_SIZE)
        return;
    if (off >= BUF_SIZE)
        return;
    FUNC1(idx);
    FUNC1(off);
}
```

- [ ] **Step 3: 核对行号**

Run: `sed -n '7p;11p;12p;15p;17p;20p' test_fixtures/multi_call_site/test.c`

Expected:
```
void FUNC0(uint32_t idx, uint32_t off)
    FUNC1(idx);               /* 调用点1：实参已校验 */
    FUNC1(off);               /* 调用点2：实参未校验 → 漏洞经此触发 */
void FUNC1(uint32_t v)
    g_buf[v] = 0xAA;          /* 危险使用点 */
void FUNC2(uint32_t idx, uint32_t off)  /* 对照链：两个调用点均已校验 */
```

- [ ] **Step 4: 写入 multi01.json**

文件 `test_fixtures/multi_call_site/multi01.json`：

```json
{
    "FUNC0$multi01": [
        [
            {"func": "FUNC0", "file": "test_fixtures/multi_call_site/test.c", "begin_line": "7"},
            {"func": "FUNC1", "file": "test_fixtures/multi_call_site/test.c", "begin_line": "15"}
        ],
        [
            {"func": "FUNC0", "file": "test_fixtures/multi_call_site/test.c", "begin_line": "7"},
            {"func": "FUNC2", "file": "test_fixtures/multi_call_site/test.c", "begin_line": "20"}
        ]
    ]
}
```

- [ ] **Step 5: 验证 JSON 可解析**

Run: `python3 -m json.tool test_fixtures/multi_call_site/multi01.json > /dev/null && echo JSON_OK`

Expected: `JSON_OK`

- [ ] **Step 6: 提交夹具文件**

```bash
git add test_fixtures/multi_call_site/test.c test_fixtures/multi_call_site/multi01.json
git commit -m "test: add multi_call_site fixture for taint-tree-checker call-site tracking"
```

---

### Task 2: 基线运行（确认当前技能漏报）

**Files:**
- 产出（不入库）: `test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`

- [ ] **Step 1: 用当前（未优化）技能运行**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/multi_call_site multi01.json`

- [ ] **Step 2: 记录基线结论**

Read `test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`，记录"结论"行。

Expected：基线报告漏洞数 = 0（结论"未发现安全漏洞"）——旧技能按"函数"套用校验结论，只看到调用点1已校验，漏报调用点2。若基线已报出 1 个漏洞，说明旧技能偶尔能检出该场景，暂停并重新审视夹具是否能稳定复现问题；若基线报出 2 个及以上漏洞（如误报调用点1或 FUNC2 链），同样暂停审视。

- [ ] **Step 3: 保留基线报告供对比**

Run: `cp test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md /tmp/multi01_baseline_result.md`

---

### Task 3: 修改 SKILL.md 第五章（流程重构 + 调用点区分 + 交叉引用）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（第五章全章 + 4.2 一处 + 第六章两处 + 9.1 两处）

- [ ] **Step 1: 替换第五章引言**

old_string（Edit 工具，文件 `taint-tree-checker/SKILL.md`）:

```
## 五、危险使用点与校验检查

在之前输出的污点传播数据流路线中，寻找污点数据的危险使用点并进行污点数据的校验检查，挖掘因外部污点数据未正确校验导致的安全漏洞。
```

new_string:

```
## 五、危险使用点与校验检查

本章以第四步输出的污点传播数据流路线为输入，按以下流程挖掘因外部污点数据未正确校验导致的安全漏洞：**分析范围确定 → 危险使用点定位 → 校验存在性检查 → 校验完备性检查 → 漏洞分析**。漏洞分析产出的候选漏洞，须通过第六章"漏洞判定门禁"方可上报。
```

- [ ] **Step 2: 插入 5.1 分析范围确定，原 5.1 标题改为 5.2 危险使用点定位**

old_string:

```
### 5.1 危险使用模式清单
```

new_string:

```
### 5.1 分析范围确定

以第四步的污点传播数据流路线为基础，确定本章的分析对象。**分析单元是"调用点"，不是"函数"。**

调用树中的一条边（如 a→b）只表示"存在调用关系"，**不代表"只调用一次"**。调用方可能多次调用同一函数，各调用点的实参不同、校验情况也不同。

- **逐调用点枚举**：回到调用方源码，枚举对同一函数（以及函数内对下游函数）的**全部调用点**，逐一纳入分析范围。不得因"树中只有一条边"只分析一次。
- **逐调用点绑定实参**：每个调用点独立完成实参→形参绑定。形参的污点状态按调用点区分：同一函数在某次调用中形参为污点、另一次调用中已校验，两种状态并存、分别追踪。
- **逐调用点成对分析**：同一条数据流经不同调用点到达同一使用点时，每个"调用点→使用点"组合都是独立分析对象。

### 5.2 危险使用点定位
```

- [ ] **Step 3: 原 5.2 标题改为 5.3 校验存在性检查，并补开头衔接句**

old_string:

```
### 5.2 校验识别清单

你必须在每个污点使用点之前，检查是否存在以下任何形式的校验。
```

new_string:

```
### 5.3 校验存在性检查

对 5.2 定位到的每个危险使用点，逐一检查其每个调用点（见 5.1）的实参在到达使用点前是否存在任何形式的校验。

你必须在每个污点使用点之前，检查是否存在以下任何形式的校验。
```

- [ ] **Step 4: 原 5.3 标题改为 5.4 校验完备性检查**

old_string:

```
### 5.3 校验完备性检查
```

new_string:

```
### 5.4 校验完备性检查
```

- [ ] **Step 5: 原 5.4 排除清单改为 5.5 漏洞分析（含 5.5.1、5.5.2）**

old_string:

```
### 5.4 排除清单（不关注的问题类型）

以下类型的问题**禁止**作为漏洞上报：
```

new_string:

```
### 5.5 漏洞分析

汇总 5.2~5.4 的结果，形成候选漏洞并完成影响分析。

#### 5.5.1 无校验或校验不完备的危险使用定位

对每个"调用点→使用点"组合：无校验，或校验不完备（按 5.4 判定，须给出具体绕过路径）→ 记为候选漏洞。

**任一调用点未正确校验即构成触发路径。一个调用点前的校验只覆盖该调用点——"第一次调用已校验"不代表"第二次调用已校验"。**

候选漏洞的攻击路径必须落在未正确校验的调用点上，并标注该调用点的行号。

#### 5.5.2 漏洞影响分析与类型排除

对候选漏洞分析安全影响（内存破坏、权限提升、信息泄露、代码执行），并按下表排除不关注的问题类型。

以下类型的问题**禁止**作为漏洞上报：
```

- [ ] **Step 6: 章末插入衔接句（排除清单最后一个列表项之后、`---` 之前）**

old_string:

```
- 密码学相关问题（Cryptography）

---
```

new_string:

```
- 密码学相关问题（Cryptography）

通过 5.5 的候选漏洞，上报前必须逐一通过第六章"漏洞判定门禁"三问，任一条件存疑则不上报。

---
```

- [ ] **Step 7: 同步 6 处交叉引用（逐处 Edit）**

7a. old_string: `（见5.3②）` → new_string: `（见5.4②）`

7b. old_string: `按 5.3 继续检查` → new_string: `按 5.4 继续检查`

7c. old_string:

```
与 5.1 整数安全模式的交叉验证：校验通过后仍进入 5.1 中"污点参与乘法/加法"等危险模式时，按本节检查运算是否使校验失效。
```

new_string:

```
与 5.2 整数安全模式的交叉验证：校验通过后仍进入 5.2 中"污点参与乘法/加法"等危险模式时，按本节检查运算是否使校验失效。
```

7d. old_string: `按 5.2 清单检查` → new_string: `按 5.3 清单检查`

7e. old_string: `按 5.3 清单检查校验是否可被绕过` → new_string: `按 5.4 清单检查校验是否可被绕过`

7f. old_string: `仍按 5.3 检查` → new_string: `仍按 5.4 检查`

- [ ] **Step 8: 9.1 思维陷阱新增一行（"链 A 已校验过…"行之后）**

old_string:

```
| "链 A 已校验过这个变量，链 B 同样使用所以也安全" | 各链共享入口函数不等于共享校验结论。各链独立确认校验，不得把链 A 的校验结论套用到链 B |
```

new_string:

```
| "链 A 已校验过这个变量，链 B 同样使用所以也安全" | 各链共享入口函数不等于共享校验结论。各链独立确认校验，不得把链 A 的校验结论套用到链 B |
| "这个函数只有一条边，分析一次就够了" | 同一条边可对应多个调用点。同函数多次调用、实参不同时，逐调用点绑定污点与校验（见 5.1），任一调用点未正确校验即构成漏洞 |
```

- [ ] **Step 9: 确认章节编号与残留引用**

Run: `grep -n "^### 5\.\|^#### 5\." taint-tree-checker/SKILL.md`

Expected：
```
### 5.1 分析范围确定
### 5.2 危险使用点定位
### 5.3 校验存在性检查
### 5.4 校验完备性检查
### 5.5 漏洞分析
#### 5.5.1 无校验或校验不完备的危险使用定位
#### 5.5.2 漏洞影响分析与类型排除
```

Run: `grep -n "5\.3 排除清单\|见5\.3②\|与 5\.1 整数安全\|按 5\.2 清单\|仍按 5\.3\|按 5\.3 清单检查校验\|按 5\.3 继续检查" taint-tree-checker/SKILL.md; true`

Expected：无输出（所有旧引用均已同步）。

- [ ] **Step 10: 提交 SKILL.md 改动**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: distinguish call sites in taint-tree-checker chapter 5 analysis flow"
```

---

### Task 4: 用优化后技能重跑夹具并核对

**Files:**
- 产出（本任务核对后，Task 5 入库）: `test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`

- [ ] **Step 1: 移除基线结果（技能有预查重，不删会直接跳过）**

Run: `rm test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`

- [ ] **Step 2: 重跑技能**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/multi_call_site multi01.json`

- [ ] **Step 3: 核对报告硬指标**

Read `test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`，逐项核对：

1. 结论行 = "发现 1 个安全漏洞"。
2. 漏洞 ID 恰为 `TAINT-6279b391`（所在函数 FUNC1、关键行号 17），仅报告一次。
3. 攻击路径经过调用点2：路径中 FUNC1 步骤的行号必须是 12（`FUNC1(off)` 所在行），不是 11。
4. 漏洞原理说明"调用点1（FUNC1(idx)，行11）实参已校验、调用点2（FUNC1(off)，行12）实参未校验"，并论证 off 可取 0~0xFFFFFFFF 任意值导致 OOB Write。
5. 报告不含 FUNC2 相关漏洞（对照链两个调用点均已校验，不应误报）。

**任一指标不符，进入 debugging 流程定位是 SKILL.md 文案问题还是执行问题，修复后从 Step 1 重跑。**

- [ ] **Step 4: 与基线对比**

Run: `diff <(grep -c "^### 漏洞" /tmp/multi01_baseline_result.md) <(grep -c "^### 漏洞" test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md); true`

人工确认：新报告漏洞数（1）> 基线漏洞数（0），说明优化生效。

---

### Task 5: 固化预期报告并回归现有夹具

**Files:**
- Create（入库）: `test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md`
- 回归比对: `test_fixtures/tree_test/.ethunter_out/`、`test_fixtures/tree_repair/.ethunter_out/`、`test_fixtures/callback_fanout/.ethunter_out/`

- [ ] **Step 1: 入库预期报告（注意 -f）**

```bash
git add -f test_fixtures/multi_call_site/.ethunter_out/taint-tree-checker/multi01_result.md
git commit -m "test: add expected report for multi_call_site fixture"
```

- [ ] **Step 2: 备份现有夹具输出**

```bash
mv test_fixtures/tree_test/.ethunter_out /tmp/tree_test_ethunter_backup
mv test_fixtures/tree_repair/.ethunter_out /tmp/tree_repair_ethunter_backup
mv test_fixtures/callback_fanout/.ethunter_out /tmp/callback_fanout_ethunter_backup
```

- [ ] **Step 3: 重跑 tree_test**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_test ef4ebf80.json`

- [ ] **Step 4: 重跑 tree_repair**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_repair repair01.json`

- [ ] **Step 5: 重跑 callback_fanout**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/callback_fanout fanout01.json`

- [ ] **Step 6: 回归比对（忽略"分析时间"行）**

```bash
diff <(grep -v "分析时间" tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md) \
     <(grep -v "分析时间" /tmp/tree_test_ethunter_backup/taint-tree-checker/ef4ebf80_result.md) | head -40
diff <(grep -v "分析时间" tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md) \
     <(grep -v "分析时间" /tmp/tree_repair_ethunter_backup/taint-tree-checker/repair01_result.md) | head -40
diff <(grep -v "分析时间" callback_fanout/.ethunter_out/taint-tree-checker/fanout01_result.md) \
     <(grep -v "分析时间" /tmp/callback_fanout_ethunter_backup/taint-tree-checker/fanout01_result.md) | head -40
```

Expected：三份 diff 为空或仅有极小措辞差异。核对要点：
- 漏洞 ID 集合与入库版完全一致（tree_test: `TAINT-661d88c5`、`TAINT-6d8cda29`；callback_fanout: `TAINT-fd593ace`、`TAINT-0f4173ae`；tree_repair 与入库 repair01_result.md 一致）。
- 结论行漏洞数一致。
- 若出现新报/漏报，进入 debugging 定位：确认是第五章重构引起的误报/漏报（需修订文案）还是执行波动（重跑一次观察）。

- [ ] **Step 7: （可选）重跑 insufficient_check 并比对**

```bash
cp test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md /tmp/bypass01_backup.md
rm test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md
```

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/insufficient_check bypass01.json`

Expected：漏洞 ID 恰为 `TAINT-8ee72c47`、`TAINT-ba4f59e4`，各一次。比对（忽略"分析时间"行）后恢复入库版：

```bash
diff <(grep -v "分析时间" test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md) \
     <(grep -v "分析时间" /tmp/bypass01_backup.md) | head -40
cp /tmp/bypass01_backup.md test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md
```

（若不做此步，跳过即可——spec 的回归范围是 tree_test、tree_repair、callback_fanout。）

- [ ] **Step 8: 恢复备份**

```bash
rm -rf test_fixtures/tree_test/.ethunter_out test_fixtures/tree_repair/.ethunter_out test_fixtures/callback_fanout/.ethunter_out
mv /tmp/tree_test_ethunter_backup test_fixtures/tree_test/.ethunter_out
mv /tmp/tree_repair_ethunter_backup test_fixtures/tree_repair/.ethunter_out
mv /tmp/callback_fanout_ethunter_backup test_fixtures/callback_fanout/.ethunter_out
git status --short   # 预期无改动（.ethunter_out 被忽略且已恢复原状）
```

---

### Task 6: 收尾自检

- [ ] **Step 1: 全量状态检查**

Run: `git status --short && git log --oneline -6`

Expected：工作区干净（rr1.txt/rr2.txt 为既有未跟踪文件，不处理）；最近提交依次为预期报告、SKILL.md 优化、夹具三个新提交。

- [ ] **Step 2: 核对 SKILL.md 引用一致性**

Run: `grep -n "5\.[0-9]" taint-tree-checker/SKILL.md`

人工核对清单（重编号后的引用应全部为）：
- 4.2：`（见5.4②）`
- 5.3 章末句：`按 5.4 继续检查`
- 5.4 末尾：`与 5.2 整数安全模式的交叉验证…进入 5.2 中`
- 第六章第 2 问 a：`按 5.3 清单`；第 2 问 b：`按 5.4 清单`
- 9.1"if 校验"行：`仍按 5.4 检查`；9.1 新行：`（见 5.1）`
- 5.1/5.3/5.5 内部互引：`见 5.1`、`对 5.2 定位到的`、`按 5.4 判定`、`汇总 5.2~5.4`

- [ ] **Step 3: 完成**

计划结束。产出：SKILL.md 第五章流程重构与调用点区分（1 次提交）、新夹具与预期报告（2 次提交）、回归验证通过（3 个既有夹具，可选第 4 个）。
