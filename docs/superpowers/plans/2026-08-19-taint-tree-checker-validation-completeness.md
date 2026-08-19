# taint-tree-checker 校验完备性检查实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 taint-tree-checker 的判定语义从"未校验"升级为"未正确校验"，新增校验完备性检查清单，并用新夹具场景验证。

**Architecture:** 本计划修改一个提示词文件（`taint-tree-checker/SKILL.md`）并新增一个测试夹具。SKILL.md 改动分四处：措辞（第3、213行）、新增 5.3 校验完备性检查（原 5.3 排除清单顺延为 5.4）、第六章门禁第2问升级为两步判定、报告模板与思维陷阱联动。夹具 `test_fixtures/insufficient_check/` 含两个校验可绕过的漏洞案例与一个完备校验对照案例，以 TDD 方式先建夹具（基线漏报）→ 改 SKILL.md → 重跑验证。

**Tech Stack:** Markdown 提示词文件；验证方式为在 Claude Code 会话中通过 Skill 工具调用 `/taint-tree-checker`；git 提交。

**设计规格:** `docs/superpowers/specs/2026-08-19-taint-tree-checker-validation-completeness-design.md`

**工作目录:** `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker`（本计划所有相对路径均以此为根）

---

## 执行约定

- 调用技能方式：使用 Skill 工具，skill 名 `taint-tree-checker`，args 为 `<project_dir> <tree_file>`，从仓库根目录发起。示例：args = `test_fixtures/insufficient_check bypass01.json`。
- 技能会预查重：`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 已存在则跳过。重跑前必须先移走/删除旧结果文件。
- 报告中的"分析时间"每次运行不同，比对时忽略该行。
- 漏洞 ID 已预先算定（sha256 前 8 位 hex，输入 `{绝对路径}:{函数}:{行号}`）：
  - 案例1 `g_buf[idx] = 0xAA`：`/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c:FUNC1:18` → **TAINT-8ee72c47**
  - 案例2 `g_buf[idx] = 0xBB`：`/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c:FUNC2:25` → **TAINT-ba4f59e4**
- 夹具预期结果入库需 `git add -f`（.gitignore 忽略 `.ethunter_out/`，沿用 tree_repair 惯例）。

---

### Task 1: 创建夹具场景（test.c 与 bypass01.json）

**Files:**
- Create: `test_fixtures/insufficient_check/test.c`
- Create: `test_fixtures/insufficient_check/bypass01.json`

- [ ] **Step 1: 创建目录**

Run: `mkdir -p test_fixtures/insufficient_check`

- [ ] **Step 2: 写入 test.c（逐字节与下行一致，行号与 JSON 强相关）**

文件 `test_fixtures/insufficient_check/test.c`：

```c
#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];

void FUNC0(uint32_t idx, uint32_t off, uint32_t len)
{
    if (len == 0)      FUNC1(idx, off);   /* 链1 */
    else if (len == 1) FUNC2(idx);        /* 链2 */
    else               FUNC3(len);        /* 链3 */
}

void FUNC1(uint32_t idx, uint32_t off)    /* 案例1：整数回绕绕过 */
{
    if (idx + off >= BUF_SIZE)            /* 校验表达式本身溢出 */
        return;
    g_buf[idx] = 0xAA;                    /* idx=UINT32_MAX, off=2 → 回绕通过 → OOB */
}

void FUNC2(int32_t idx)                   /* 案例2：只查上界，负数绕过 */
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xBB;                    /* idx=-1 → OOB */
}

void FUNC3(uint32_t len)                  /* 案例3：对照——校验完备，不应报 */
{
    if (len >= BUF_SIZE)
        return;
    g_buf[len] = 0xCC;                    /* uint32 无负数，上界检查即完备 */
}
```

- [ ] **Step 3: 核对行号**

Run: `sed -n '7p;14p;18p;21p;25p;28p;32p' test_fixtures/insufficient_check/test.c`

Expected:
```
void FUNC0(uint32_t idx, uint32_t off, uint32_t len)
void FUNC1(uint32_t idx, uint32_t off)    /* 案例1：整数回绕绕过 */
    g_buf[idx] = 0xAA;                    /* idx=UINT32_MAX, off=2 → 回绕通过 → OOB */
void FUNC2(int32_t idx)                   /* 案例2：只查上界，负数绕过 */
    g_buf[idx] = 0xBB;                    /* idx=-1 → OOB */
void FUNC3(uint32_t len)                  /* 案例3：对照——校验完备，不应报 */
    g_buf[len] = 0xCC;                    /* uint32 无负数，上界检查即完备 */
```

- [ ] **Step 4: 写入 bypass01.json**

文件 `test_fixtures/insufficient_check/bypass01.json`：

```json
{
    "FUNC0$bypass01": [
        [
            {"func": "FUNC0", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "7"},
            {"func": "FUNC1", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "14"}
        ],
        [
            {"func": "FUNC0", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "7"},
            {"func": "FUNC2", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "21"}
        ],
        [
            {"func": "FUNC0", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "7"},
            {"func": "FUNC3", "file": "test_fixtures/insufficient_check/test.c", "begin_line": "28"}
        ]
    ]
}
```

- [ ] **Step 5: 验证 JSON 可解析**

Run: `python3 -m json.tool test_fixtures/insufficient_check/bypass01.json > /dev/null && echo JSON_OK`

Expected: `JSON_OK`

- [ ] **Step 6: 提交夹具文件**

```bash
git add test_fixtures/insufficient_check/test.c test_fixtures/insufficient_check/bypass01.json
git commit -m "test: add insufficient_check fixture for taint-tree-checker validation-completeness"
```

---

### Task 2: 基线运行（确认当前技能漏报）

**Files:**
- 产出（不入库）: `test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`

- [ ] **Step 1: 用当前（未优化）技能运行**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/insufficient_check bypass01.json`

- [ ] **Step 2: 记录基线结论**

Read `test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`，记录"结论"行。

Expected：基线报告漏洞数 ≤ 1（案例1 的 `idx + off >= BUF_SIZE` 整数回绕在旧技能下几乎必然被当作"已校验"而漏报）。若基线报告了 2 个漏洞，说明旧技能已能检出，需重新审视本计划的价值并暂停；若 0 个，说明两个案例都漏报，正符合预期。

- [ ] **Step 3: 保留基线报告供对比**

Run: `cp test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md /tmp/bypass01_baseline_result.md`

---

### Task 3: 修改 SKILL.md 措辞（2 处）

**Files:**
- Modify: `taint-tree-checker/SKILL.md:3`
- Modify: `taint-tree-checker/SKILL.md:213`

- [ ] **Step 1: 改 frontmatter description（第 3 行）**

old_string（Edit 工具，文件 `taint-tree-checker/SKILL.md`）:

```
description: 使用命令 /taint-tree-checker 触发。分析C语言函数调用树（以同一入口函数为起点的多条调用链）中的外部输入（污点数据）传播路径，挖掘因未校验导致的安全漏洞。适用于嵌入式/底层系统代码（Linux内核驱动、UEFI/BL31/BL2/XLoader、ISP/SensorHub/GPU固件）。
```

new_string:

```
description: 使用命令 /taint-tree-checker 触发。分析C语言函数调用树（以同一入口函数为起点的多条调用链）中的外部输入（污点数据）传播路径，挖掘因未正确校验导致的安全漏洞。适用于嵌入式/底层系统代码（Linux内核驱动、UEFI/BL31/BL2/XLoader、ISP/SensorHub/GPU固件）。
```

- [ ] **Step 2: 改第五章引言（第 213 行）**

old_string:

```
在之前输出的污点传播数据流路线中，寻找污点数据的危险使用点并进行污点数据的校验检查，挖掘因外部污点数据未校验导致的安全漏洞。
```

new_string:

```
在之前输出的污点传播数据流路线中，寻找污点数据的危险使用点并进行污点数据的校验检查，挖掘因外部污点数据未正确校验导致的安全漏洞。
```

- [ ] **Step 3: 确认改动**

Run: `git diff --stat taint-tree-checker/SKILL.md && grep -n "未正确校验" taint-tree-checker/SKILL.md`

Expected：diff 显示 2 处插入 2 处删除；grep 命中第 3、213 行。

---

### Task 4: 新增 5.3 校验完备性检查（排除清单顺延为 5.4）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（5.2 末尾与 5.3 标题之间插入）

- [ ] **Step 1: 在 5.2 末尾补一句衔接**

old_string（5.2 嵌入式特有校验模式表格后的 `### 5.3 排除清单` 标题前，需包含标题行以定位）:

```
| 长度交叉校验 | `if (hdr->len != computed_len)` → 长度一致性验证 |

### 5.3 排除清单（不关注的问题类型）
```

new_string:

```
| 长度交叉校验 | `if (hdr->len != computed_len)` → 长度一致性验证 |

存在上述任一形式的校验，仅说明"有校验"；校验是否完备、能否被绕过，按 5.3 继续检查。

### 5.3 校验完备性检查

**存在校验 ≠ 校验有效。** 对每个"已校验"的污点使用点，还必须检查校验是否完备、是否可被绕过。**上报门槛：必须给出具体的绕过输入或溢出路径**，论证不通的视为校验有效（宁可漏报，不要误报）。检查以下缺陷模式：

#### ① 边界缺陷

| 缺陷 | 示例 | 绕过方式 |
|------|------|----------|
| 只查上界不查下界 | `if (idx >= BUF_SIZE) return; buf[idx]` | idx 为负数（有符号）时绕过 |
| 只查下界不查上界 | `if (idx < 0) return; buf[idx]` | idx 取极大值 |
| 边界差一 | `if (idx <= BUF_SIZE)` | idx == BUF_SIZE 越界一元素 |
| 校验常量与实际不一致 | `if (len < 64)` 但缓冲区为 32 | 硬编码错误常量 |

#### ② 整数溢出/类型混淆绕过

| 缺陷 | 示例 | 绕过方式 |
|------|------|----------|
| 校验表达式本身溢出 | `if (idx + off < MAX); buf[idx]` | idx+off 回绕为小值通过校验 |
| 校验后参与运算溢出 | `if (size < MAX); alloc(size * elem)` | size 合法但乘积溢出→分配过小 |
| 乘法结果校验顺序颠倒 | `total = cnt * sz; if (total < MAX)` | 溢出后 total 变小通过校验 |
| 有符号/无符号错配 | `if (len < 0) return;` 而 len 为 uint32 | 恒假，极大值不拦截 |

#### ③ 校验对象与时序错位

| 缺陷 | 示例 | 绕过方式 |
|------|------|----------|
| 校验的变量 ≠ 使用的变量 | 校验 `len`，使用 `len+1` | 实际值超出校验范围 |
| 校验字段 A 但使用字段 B | 校验 `hdr->total_len`，使用 `hdr->payload_len` | B 未受约束（无交叉约束时） |
| 校验副本但使用原始值 | `safe = v; if (safe<MAX); use(v)` | v 经别名在校验后被修改 |
| 校验时机在使用之后 | 先 `buf[idx]` 后 `if (idx>=MAX)` | 校验晚于危险使用 |
| 部分校验 | 校验 `len` 不校验 `off`，使用 `buf[off+len]` | off 独立控制 |

与 5.1 整数安全模式的交叉验证：校验通过后仍进入 5.1 中"污点参与乘法/加法"等危险模式时，按本节检查运算是否使校验失效。

### 5.4 排除清单（不关注的问题类型）
```

- [ ] **Step 2: 确认编号顺延**

Run: `grep -n "^### 5\." taint-tree-checker/SKILL.md`

Expected：
```
### 5.1 危险使用模式清单
### 5.2 校验识别清单
### 5.3 校验完备性检查
### 5.4 排除清单（不关注的问题类型）
```

---

### Task 5: 4.2 类型转换行补充符号性提示（规格外小扩展，支撑夹具案例2）

**Files:**
- Modify: `taint-tree-checker/SKILL.md:137`

说明：夹具案例 2 依赖"uint32 实参隐式转换到 int32 形参后符号性翻转"的追踪；原 4.2 只写"强转不消除污点"，未提示记录符号性。此改动是规格批准内容的最小必要补充。

- [ ] **Step 1: 修改类型转换行**

old_string:

```
| 类型转换 | `b = (uint32_t)a;` | 强转不消除污点 |
```

new_string:

```
| 类型转换 | `b = (uint32_t)a;` | 强转不消除污点；转换改变符号性/宽度时须记录之（含实参到形参的隐式转换），符号性变化可能使后续校验失效（见5.3②） |
```

- [ ] **Step 2: 确认改动**

Run: `grep -n "符号性" taint-tree-checker/SKILL.md`

Expected：命中第 137 行附近一行。

---

### Task 6: 门禁第 2 问升级为两步判定

**Files:**
- Modify: `taint-tree-checker/SKILL.md:328`

- [ ] **Step 1: 替换门禁第 2 问**

old_string:

```
2. **未校验**：在污点数据到达危险使用点之前，是否存在上述任何形式的校验（显式或隐式）？**仔细检查隐式校验，宁可误判有校验也不要漏判。**
```

new_string:

```
2. **未正确校验**：在污点数据到达危险使用点之前，校验是否存在且完备有效？分两步判定：

   a. **是否存在校验**：按 5.2 清单检查任何形式的校验（显式或隐式）。仔细检查隐式校验，宁可误判有校验也不要漏判。
   b. **校验是否完备**：按 5.3 清单检查校验是否可被绕过（边界不完整、整数溢出回绕、类型混淆、校验对象与时序错位等）。**必须给出具体绕过输入或溢出路径才能判定校验无效**；论证不通的视为校验有效（宁可漏报，不要误报）。
```

- [ ] **Step 2: 确认改动**

Run: `grep -n "未正确校验\|校验是否完备" taint-tree-checker/SKILL.md`

Expected：第六章区域出现"未正确校验"与两步判定文案。

---

### Task 7: 报告模板与思维陷阱联动

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（7.3 末句、7.4 漏洞原理、9.1 两行）

- [ ] **Step 1: 7.3 无漏洞模板末句**

old_string:

```
该调用树的外部输入在各条调用链传播过程中，均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。
```

new_string:

```
该调用树的外部输入在各条调用链传播过程中，均已在关键使用点前经过正确校验，未发现可被利用的安全漏洞。
```

- [ ] **Step 2: 7.4 漏洞原理字段要求**

old_string:

```
（详细说明污点数据从入口函数参数到漏洞点的完整传播路径。逐层追踪每个变量的污染状态，列出校验点及其覆盖/未覆盖的变量。）
```

new_string:

```
（详细说明污点数据从入口函数参数到漏洞点的完整传播路径。逐层追踪每个变量的污染状态，列出校验点及其覆盖/未覆盖的变量；若校验存在但不完备，须说明校验为何不完备/被绕过的方式——给出具体绕过输入或溢出路径。）
```

- [ ] **Step 3: 9.1 更新"校验不足也是一种漏洞"行**

old_string:

```
| "校验不足也是一种漏洞" | 校验不足是根因，不是独立漏洞。只报因校验不足导致的**具体安全后果**（如缓冲区溢出），在漏洞原理中说明是校验缺失导致的。不要报告"漏洞：输入校验不充分（中危）" |
```

new_string:

```
| "校验不足也是一种漏洞" | 校验不足是根因，不是独立漏洞。只报因校验缺失或不完备导致的**具体安全后果**（如缓冲区溢出），在漏洞原理中说明根因并给出绕过论证。不要报告"漏洞：输入校验不充分（中危）" |
| "这里已经有 if 校验了，所以安全" | 存在校验≠校验有效。仍按 5.3 检查校验是否完备、是否可被绕过（整数回绕、符号性错配、校验对象错位等）；须能给出具体绕过输入才可推翻 |
```

- [ ] **Step 4: 确认三处改动**

Run: `grep -n "正确校验\|被绕过的方式\|存在校验≠校验有效" taint-tree-checker/SKILL.md`

Expected：三处各命中一行。

- [ ] **Step 5: 提交 SKILL.md 全部改动**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: upgrade taint-tree-checker gate to validation completeness"
```

---

### Task 8: 用优化后技能重跑夹具并核对

**Files:**
- 产出（本任务核对后，Task 9 入库）: `test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`

- [ ] **Step 1: 移除基线结果（技能有预查重，不删会直接跳过）**

Run: `rm test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`

- [ ] **Step 2: 重跑技能**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/insufficient_check bypass01.json`

- [ ] **Step 3: 核对报告硬指标**

Read `test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`，逐项核对：

1. 结论行 = "发现 2 个安全漏洞"。
2. 漏洞 ID 恰为 `TAINT-8ee72c47`（所在函数 FUNC1、关键行号 18）与 `TAINT-ba4f59e4`（所在函数 FUNC2、关键行号 25），各报告一次，无重复。
3. 漏洞 1 的漏洞原理给出整数回绕绕过论证（如 idx=0xFFFFFFFF、off=2 → idx+off 回绕为 1 通过校验）。
4. 漏洞 2 的漏洞原理给出符号性绕过论证（uint32 0xFFFFFFFF 隐式转换为 int32 -1，`idx >= BUF_SIZE` 不拦截负数）。
5. 分析情况说明 FUNC3（链3）校验完备、未报告漏洞；报告不含 FUNC3:32 的漏洞。

**任一指标不符，进入 debugging 流程定位是 SKILL.md 文案问题还是执行问题，修复后从 Step 1 重跑。**

- [ ] **Step 4: 与基线对比**

Run: `diff <(grep -c "^### 漏洞" /tmp/bypass01_baseline_result.md) <(grep -c "^### 漏洞" test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md); true`

人工确认：新报告漏洞数 > 基线漏洞数（基线 ≤ 1，新报告 = 2），说明优化生效。

---

### Task 9: 固化预期报告并回归现有夹具

**Files:**
- Create（入库）: `test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md`
- 回归比对: `test_fixtures/tree_test/.ethunter_out/`、`test_fixtures/tree_repair/.ethunter_out/`

- [ ] **Step 1: 入库预期报告（注意 -f）**

```bash
git add -f test_fixtures/insufficient_check/.ethunter_out/taint-tree-checker/bypass01_result.md
git commit -m "test: add expected report for insufficient_check fixture"
```

- [ ] **Step 2: 备份现有夹具输出**

```bash
mv test_fixtures/tree_test/.ethunter_out /tmp/tree_test_ethunter_backup
mv test_fixtures/tree_repair/.ethunter_out /tmp/tree_repair_ethunter_backup
```

- [ ] **Step 3: 重跑 tree_test**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_test ef4ebf80.json`

- [ ] **Step 4: 重跑 tree_repair**

调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_repair repair01.json`

- [ ] **Step 5: 回归比对（忽略"分析时间"行）**

```bash
diff <(grep -v "分析时间" tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md) \
     <(grep -v "分析时间" /tmp/tree_test_ethunter_backup/taint-tree-checker/ef4ebf80_result.md) | head -40
diff <(grep -v "分析时间" tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md) \
     <(grep -v "分析时间" /tmp/tree_repair_ethunter_backup/taint-tree-checker/repair01_result.md) | head -40
```

Expected：两份 diff 为空或仅有极小措辞差异。核对要点：
- 漏洞 ID 集合与入库版完全一致（tree_test: TAINT-661d88c5、TAINT-6d8cda29；tree_repair: 与入库 repair01_result.md 一致）。
- 结论行漏洞数一致。
- 若出现新报/漏报，进入 debugging 定位：确认是 5.3 新清单引起误报（需修订文案）还是执行波动（重跑一次观察）。

- [ ] **Step 6: 恢复备份**

```bash
rm -rf test_fixtures/tree_test/.ethunter_out test_fixtures/tree_repair/.ethunter_out
mv /tmp/tree_test_ethunter_backup test_fixtures/tree_test/.ethunter_out
mv /tmp/tree_repair_ethunter_backup test_fixtures/tree_repair/.ethunter_out
git status --short   # 预期无改动（.ethunter_out 被忽略且已恢复原状）
```

---

### Task 10: 收尾自检

- [ ] **Step 1: 全量 diff 检查**

Run: `git status --short && git diff HEAD -- taint-tree-checker/SKILL.md | head -5`

Expected：工作区干净（rr1.txt/rr2.txt 为既有未跟踪文件，不处理）。

- [ ] **Step 2: 核对执行检查清单（SKILL.md 第八章）与本次改动无冲突**

Read `taint-tree-checker/SKILL.md` 第八章与第九章，确认编号（5.3/5.4）、门禁三问表述、模板引用前后一致，无残留"5.3 排除清单"旧引用。

Run: `grep -n "5\.3 排除\|5\.4" taint-tree-checker/SKILL.md`

Expected：无"5.3 排除"字样；5.4 仅一处。

- [ ] **Step 3: 完成**

计划结束。产出：SKILL.md 优化（3 次提交）、新夹具与预期报告（2 次提交）、回归验证通过。
