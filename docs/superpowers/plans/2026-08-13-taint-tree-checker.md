# taint-tree-checker 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新建 markdown skill `taint-tree-checker`——将 taint-path-checker 的单链分析扩展为调用树（同一入口函数的多条链）分析，下游 taint-path-cleaner 零改动。

**Architecture:** 复制 `taint-path-checker/SKILL.md` 为模板，改写输入解析（树 JSON）、逐链独立污点追踪、树级报告模板（TreeID）；通过 `.claude/skills/taint-tree-checker/SKILL.md` 符号链接注册 skill（本地配置，`.claude/` 已被 gitignore）。

**Tech Stack:** 纯 Markdown 文档（无代码）；bash（目录/符号链接/grep 校验）；python3（JSON 校验）；`claude -p`（端到端试跑）。

**设计规格：** `docs/superpowers/specs/2026-08-13-taint-tree-checker-design.md`

**测试约定：** 本项目为文档型 skill，无传统单元测试。"测试"= 构造夹具 + `claude -p` 端到端试跑 + 对输出报告文件做内容断言。运行产物位于 `.ethunter_out/`（已被 gitignore），不参与提交。

**RED 基线结果（2026-08-13 实测，无 skill 时子代理行为）：**

| 场景 | 基线失败行为 | 代理原话（合理化借口） |
|------|--------------|------------------------|
| 基础树 | 跨链污染：把链1写入的全局 `g_flag` 当链2污点，误报 FUNC3:32 | "两条链是同一程序的运行时备选路径，链1写入的 persistent static 会流入链2" |
| 全部场景 | 输出无规范：报告写 `reports/*.md`，无 `.ethunter_out/` 目录、无 `{TreeID}_result.md` 命名、无 TAINT-{hash8} ID | 各自"定义自己的报告结构" |
| TreeID 不一致 | 不校验，继续分析并只记"低危数据完整性观察" | "`$` 后缀是用于存储/去重命名的身份哈希，纯元数据、无污点语义……仅当键中函数名无法解析时才拒绝" |
| 缺源码链 | ✓ 跳过链2并记录缺口（符合预期，保留） | "中止会丢弃链1的真实发现；静默跳过会歪曲结果" |

GREEN 验证（带 skill 试跑）：上述失败点全部纠正；5 个场景（主流程/预查重/TreeID不一致/缺源码链/单链树退化）一次通过；下游 cleaner 零改动消费树报告判定正报。REFACTOR 阶段未发现新的合理化借口，SKILL.md 无需追加修改。

---

### Task 1: 创建目录、复制模板、注册 skill

**Files:**
- Create: `taint-tree-checker/SKILL.md`（复制自 taint-path-checker）
- Create: `.claude/skills/taint-tree-checker/SKILL.md`（符号链接，本地配置，不入库）

- [ ] **Step 1: 创建目录并复制模板**

```bash
mkdir -p taint-tree-checker .claude/skills/taint-tree-checker
cp taint-path-checker/SKILL.md taint-tree-checker/SKILL.md
ln -s ../../../taint-tree-checker/SKILL.md .claude/skills/taint-tree-checker/SKILL.md
```

- [ ] **Step 2: 验证复制与链接**

```bash
ls -la .claude/skills/taint-tree-checker/
```

Expected: `SKILL.md -> ../../../taint-tree-checker/SKILL.md`

```bash
readlink -f .claude/skills/taint-tree-checker/SKILL.md
```

Expected: `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/taint-tree-checker/SKILL.md`（即与 `taint-tree-checker/SKILL.md` 同一文件）

```bash
diff taint-path-checker/SKILL.md taint-tree-checker/SKILL.md && echo "IDENTICAL"
```

Expected: `IDENTICAL`

- [ ] **Step 3: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: add taint-tree-checker skill skeleton copied from taint-path-checker"
```

---

### Task 2: 修改 frontmatter 与第一章

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（frontmatter 与第一章）

- [ ] **Step 1: 先 Read 文件确认当前文本**（后续 Edit 的 old_string 须与文件完全一致；若 Edit 报 not found，重新 Read 对应段落再适配）

- [ ] **Step 2: 替换 frontmatter**

old_string:

```
name: taint-path-checker
description: 使用命令 /taint-path-checker 触发。分析C语言函数调用链中的外部输入（污点数据）传播路径，挖掘因未校验导致的安全漏洞。适用于嵌入式/底层系统代码（Linux内核驱动、UEFI/BL31/BL2/XLoader、ISP/SensorHub/GPU固件）。
```

new_string:

```
name: taint-tree-checker
description: 使用命令 /taint-tree-checker 触发。分析C语言函数调用树（以同一入口函数为起点的多条调用链）中的外部输入（污点数据）传播路径，挖掘因未校验导致的安全漏洞。适用于嵌入式/底层系统代码（Linux内核驱动、UEFI/BL31/BL2/XLoader、ISP/SensorHub/GPU固件）。
```

- [ ] **Step 3: 替换第一章任务描述**

old_string:

```
你是一名嵌入式C代码安全分析专家。你的任务：读取一条函数调用链，追踪外部输入（污点数据）在函数间的传递过程，判断污点数据在危险使用前是否经过正确校验，最终输出一份标准化的分析报告。
```

new_string:

```
你是一名嵌入式C代码安全分析专家。你的任务：读取一棵函数调用树（以同一入口函数为起点的多条调用链），逐链追踪外部输入（污点数据）在函数间的传递过程，判断污点数据在危险使用前是否经过正确校验，最终输出一份标准化的分析报告。
```

- [ ] **Step 4: 替换漏洞挖掘范围表述**

old_string:

```
**漏洞挖掘范围**：以调用链中的函数为主体。追踪污点时进入的链外辅助函数中发现的可触发漏洞亦可报告，但须标注"链外"。与调用链无关的代码中偶然发现的漏洞不报告。
```

new_string:

```
**漏洞挖掘范围**：以调用树各链中的函数为主体。追踪污点时进入当前链之外的辅助函数中发现的可触发漏洞亦可报告，但须标注"链外"。与调用树无关的代码中偶然发现的漏洞不报告。
```

- [ ] **Step 5: 验证并提交**

```bash
git diff taint-tree-checker/SKILL.md | head -80
git add taint-tree-checker/SKILL.md
git commit -m "feat: adapt taint-tree-checker frontmatter and overview for tree input"
```

---

### Task 3: 改写第二章 输入解析

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（第二章整体替换）

- [ ] **Step 1: Read 第二章当前内容**（从 `## 二、输入解析` 到 `## 三、获取目标代码` 之前），确认 old_string 边界。

- [ ] **Step 2: 整体替换第二章**（old_string 为当前第二章全文，从 `## 二、输入解析` 起至 2.5 节结尾；new_string 如下）

new_string:

```
## 二、输入解析

### 2.1 命令格式

```
/taint-tree-checker <project_dir> <tree_file>
```

**参数说明：**

- `<project_dir>`：待分析项目的根目录路径。此参数为可选，若未提供则默认使用当前工作目录，无需向用户确认。
- `<tree_file>`：调用树描述文件的路径，格式为 JSON。文件名遵循命名约定 `{TreeID}.json`，即文件名（不含扩展名）即为该次分析任务的 TreeID。

### 2.2 调用树JSON格式

调用树文件为一个 JSON 文档，包含一个顶层键，格式为 `{入口函数名}${TreeID}`，值为调用链数组。每条链为元素数组，按调用顺序排列；**每条链的首个元素均为入口函数**，其参数为外部输入来源。链数组非空，最少包含一条链（单链树允许，退化为单链分析）。

```json
{
    "FUNC0$ef4ebf80": [
        [
            {"func": "FUNC0", "file": "/src/a.c", "begin_line": "31"},
            {"func": "FUNC1", "file": "/src/a.c", "begin_line": "156"},
            {"func": "FUNC2", "file": "/src/a.c", "begin_line": "185"}
        ],
        [
            {"func": "FUNC0", "file": "/src/a.c", "begin_line": "31"},
            {"func": "FUNC3", "file": "/src/a.c", "begin_line": "156"}
        ]
    ]
}
```

每个链元素包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| `func` | string | 函数名 |
| `file` | string | 函数所在源文件的绝对路径 |
| `begin_line` | string | 函数定义起始行号 |

**解析规则（必须逐条执行）：**

1. **TreeID 以文件名为准**：TreeID = tree_file 文件名（不含扩展名）。顶层键中 `$` 后部分必须与 TreeID 一致，不一致时在报告中报错并结束本次任务。
2. **键格式**：顶层键必须符合 `{函数名}${TreeID}` 形式（包含 `$`），否则在报告中报错并结束本次任务。
3. **入口函数名一致**：顶层键中 `$` 前部分为入口函数名，每条链首元素的 `func` 必须与之一致，不一致时在报告中报错并结束本次任务。
4. **链数组非空**：链数组必须为非空数组，否则在报告中报错并结束本次任务。

### 2.3 初始化输出目录

执行分析前，**必须先创建输出目录**：

```
{project_dir}/.ethunter_out/taint-tree-checker/
```

目录不存在则使用 `mkdir -p` 创建。

### 2.4 预查重

在开始分析之前，先检查该调用树是否已被分析过：

检查 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 是否存在 —— 若存在，说明此前已产出分析结果，跳过该调用树，直接输出提示信息并结束本次任务。

提示信息格式：

```
该调用树已有分析结果：{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md，跳过分析。
```

### 2.5 加载编译宏配置

检查 `{project_dir}/.ethunter_out/macro.json` 是否存在。若存在，读取并记住其中的宏定义（格式 `{"MACRO": "value", ...}`），这些是编译指令中动态定义的宏。若不存在则跳过，后续照常分析。
```

注意：new_string 中以三个反引号包裹的代码块在写入文件时保持原样（JSON 示例与命令格式）。

- [ ] **Step 3: 验证第二章已替换且无残留**

```bash
grep -n "callchainID\|调用链ID" taint-tree-checker/SKILL.md
```

Expected: 第二章无匹配（若有，说明替换不完整，修复后再验证）。

- [ ] **Step 4: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: rewrite input parsing chapter for tree JSON format"
```

---

### Task 4: 改写第三章 获取目标代码

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（第三章整体替换）

- [ ] **Step 1: Read 第三章当前内容确认边界（`## 三、获取目标代码` 至 `## 四、` 之前），执行整体替换，new_string 如下**

```
## 三、获取目标代码

遍历所有链，定位每个函数的源代码：

1. 根据 `file` 和 `begin_line` 定位函数定义。
2. 使用 Read 工具读取函数完整代码。若函数体较长，需分段读取直到函数结束。**同一函数在多条链中出现时（file 与 begin_line 相同），源码只读一次**，但每条链的分析独立进行。
3. 若某链中某函数源码在给定文件中不存在，**跳过该链**，继续分析其余链，在最终报告摘要中注明被跳过的链及原因。
4. 对于链外辅助函数：当污点数据传递到当前链之外的函数时，需在 project_dir 中搜索该函数的定义并分析其对污点数据的操作。但漏洞判定仍回归链内。

建议先通读所有链中函数的完整源码，建立全局数据流概览，再逐链追踪。追踪过程中发现危险使用点时，回溯前方函数确认校验状态。
```

- [ ] **Step 2: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: adapt source acquisition chapter for multi-chain iteration"
```

---

### Task 5: 改写第四章 污点数据追踪（逐链独立）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（4.1 与 4.3 局部修改，4.2 清单不动）

- [ ] **Step 1: 修改 4.1 开头，插入逐链独立规则**

old_string:

```
入口函数的所有参数默认视为污点数据。但正式开始追踪前，应先剔除明显非外部输入的参数，避免无意义追踪。以下类型可视为非外部输入：
```

new_string:

```
对每条链独立执行本节的追踪流程。**全局/静态变量污点在链间不传播**：每条链从干净的全局污点状态开始分析，链内某函数写入的全局/静态变量污点仅对同链内后续函数生效。

入口函数（当前链的首元素函数）的所有参数默认视为污点数据。但正式开始追踪前，应先剔除明显非外部输入的参数，避免无意义追踪。以下类型可视为非外部输入：
```

- [ ] **Step 2: 修改 4.3 全局/静态变量追踪条目**

old_string:

```
- **全局/静态变量追踪**：污点在链内某函数写入全局或静态变量后，链内后续函数读取该变量时视为污点传播，直到被覆盖或显式净化。
```

new_string:

```
- **全局/静态变量追踪**：污点在链内某函数写入全局或静态变量后，同链内后续函数读取该变量时视为污点传播，直到被覆盖或显式净化。跨链不传播：每条链从干净的全局污点状态开始分析。
```

- [ ] **Step 3: 验证**

```bash
grep -n "链间不传播" taint-tree-checker/SKILL.md
```

Expected: 两处匹配（4.1 与 4.3）。

- [ ] **Step 4: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: add per-chain independent taint tracking rule"
```

---

### Task 6: 改写第七章 报告输出

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（7.1/7.2/7.3/7.4 局部修改，7.5 不动）

- [ ] **Step 1: 7.1 增加树内去重规则**

old_string:

```
同一 file+func+line 组合产生相同 ID，实现跨任务去重。
```

new_string:

```
同一 file+func+line 组合产生相同 ID，实现跨任务去重。

**树内去重**：多条链发现相同漏洞 ID（同一 file:func:line）时，合并报告一次，攻击路径记录其中任一条真实可达的链。不得重复列出相同 ID 的漏洞。
```

- [ ] **Step 2: 7.2 输出路径更新**

old_string:

```
路径：`{project_dir}/.ethunter_out/taint-path-checker/{callchainID}_result.md`
```

new_string:

```
路径：`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md`
```

- [ ] **Step 3: 7.3 无漏洞模板更新**

old_string:

```
- **调用链ID**：{callchainID}
```

new_string:

```
- **调用树ID**：{TreeID}
```

old_string:

```
（简述调用链功能、污点数据追踪结果、关键校验点说明）

该调用链中的外部输入均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。
```

new_string:

```
（逐链简述各链功能、污点数据追踪结果、关键校验点；被跳过的链注明链内容与跳过原因）

该调用树各链中的外部输入均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。
```

- [ ] **Step 4: 7.4 有漏洞模板更新**（头部 + 新增"分析情况"小节）

old_string:

```
- **调用链ID**：{callchainID}
- **分析时间**：{当前时间}
- **结论**：发现 N 个安全漏洞

## 漏洞列表
```

new_string:

```
- **调用树ID**：{TreeID}
- **分析时间**：{当前时间}
- **结论**：发现 N 个安全漏洞

## 分析情况

（树内链数、各链分析状态：已分析的链逐一简述功能与关键校验；被跳过的链注明跳过原因。）

## 漏洞列表
```

- [ ] **Step 5: 验证第七章无残留**

```bash
grep -n "调用链ID\|callchainID" taint-tree-checker/SKILL.md
```

Expected: 无匹配。

- [ ] **Step 6: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: adapt report chapter for tree ID and in-tree dedup"
```

---

### Task 7: 改写第八、九章（检查清单与自检提醒）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`

- [ ] **Step 1: 第八章检查清单整体替换**（old_string 为当前第八章正文，从"在完成分析并生成报告后，执行以下检查："到"若输出文件不存在，立即创建并写入报告。"；new_string 如下）

```
在完成分析并生成报告后，执行以下检查：

1. 输出文件 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 是否存在。
2. 树内每条链是否都有结论（已分析或已跳过，跳过的注明原因）。
3. 报告的结论（有漏洞/无漏洞）是否有充分的分析依据。
4. 每个上报的漏洞是否通过了硬性检查门的三问。
5. 漏洞 ID 是否基于 file:func:line 正确生成，树内同 ID 漏洞是否已合并。
6. 是否有排除清单中的问题类型被误报。

若输出文件不存在，立即创建并写入报告。
```

- [ ] **Step 2: 9.1 思维陷阱表新增两行**（在表最后一行之后追加）

old_string:

```
| "分析太长了，后面简化一下" | 宁可多花时间确保准确，牺牲效率保证质量 |
```

new_string:

```
| "分析太长了，后面简化一下" | 宁可多花时间确保准确，牺牲效率保证质量 |
| "链 A 已校验过这个变量，链 B 同样使用所以也安全" | 各链共享入口函数不等于共享校验结论。逐链独立确认校验，不得把链 A 的校验结论套用到链 B |
| "这个漏洞在两条链里都发现了，各报一次" | 树内同 ID 漏洞（同 file:func:line）合并报告一次，攻击路径须选取确实可达的链 |
```

- [ ] **Step 3: 9.2 边缘情况表整体替换**（old_string 为当前表全文；new_string 如下）

```
| 情况 | 处理方式 |
|------|----------|
| 调用树JSON格式异常（键格式错误、TreeID 与文件名不一致、入口函数不一致、空链数组） | 在报告中报错并结束本次任务，不做分析 |
| 某链中某函数源码找不到 | 跳过该链，继续分析其余链，在摘要中注明该链内容与"函数 xxx 源码未找到，跳过该链" |
| 某链污点传播路径在某处无法追踪 | 跳过该链，其余链照常分析，在摘要中注明"变量A在函数B中污点状态无法确定" |
| 输出目录创建失败 | 尝试在当前目录下创建，确保有输出文件 |
| 结果文件已存在 | 输出跳过提示信息，不重复分析（跳过整棵树） |
| 分析不完整但无确认漏洞 | 使用无漏洞报告模板，在摘要中说明各链分析范围及中断原因。未确认的漏洞不报告 |
```

- [ ] **Step 4: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: adapt checklist and self-check chapters for tree analysis"
```

---

### Task 8: 全文一致性自检

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（仅修复残留问题，若无残留则不改）

- [ ] **Step 1: 扫描残留单链表述**

```bash
grep -n "callchainID\|调用链ID\|调用链JSON\|单条调用链\|该调用链" taint-tree-checker/SKILL.md
```

Expected: 无匹配。若有个别匹配，逐处判断：属于必须改写的（如"该调用链中的外部输入"）则改为树表述；属于合理保留的（如 2.2 中"多条调用链"、4.x 中"链内"）则不动。

- [ ] **Step 2: 扫描旧 skill 名残留**

```bash
grep -n "taint-path-checker" taint-tree-checker/SKILL.md
```

Expected: 无匹配。

- [ ] **Step 3: 通读全文**

Read `taint-tree-checker/SKILL.md` 全文，确认九章结构完整、第五章与第六章未被误改、7.5 链外标记仍在、"宁可漏报，不要误报"核心原则仍在。

- [ ] **Step 4: 确认其他文件未被改动**

```bash
git status --short
git diff HEAD -- taint-path-checker/SKILL.md taint-path-cleaner/SKILL.md
```

Expected: 两个旧 skill 文件无 diff。

- [ ] **Step 5: 提交（若有修复）或跳过**（无修改则直接进入下一任务，不产生空提交）

```bash
git add taint-tree-checker/SKILL.md
git commit -m "fix: remove leftover single-chain wording in taint-tree-checker"
```

---

### Task 9: 创建测试夹具

**Files:**
- Create: `test_fixtures/tree_test/test.c`
- Create: `test_fixtures/tree_test/ef4ebf80.json`

- [ ] **Step 1: 创建源文件 test.c**（内容如下，行号已按内容编排；`g_flag` 用于测试链间独立规则）

```c
#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];
static uint32_t g_flag;

void FUNC0(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {
        FUNC1(idx);
    } else {
        FUNC3(idx);
    }
}

void FUNC1(uint32_t idx)
{
    g_flag = idx;               /* 链1写入全局变量 */
    FUNC2(idx);
}

void FUNC2(uint32_t idx)
{
    g_buf[idx] = 0xAA;          /* 链1：idx 未校验 */
}

void FUNC3(uint32_t idx)
{
    if (idx >= BUF_SIZE)        /* 链2：idx 已校验 */
        return;
    g_buf[g_flag] = 0xCC;       /* 链2内 g_flag 未被污染（链间独立） */
}
```

- [ ] **Step 2: 验证函数起始行号**

```bash
grep -n "^void FUNC" test_fixtures/tree_test/test.c
```

Expected:

```
8:void FUNC0(uint32_t cmd, uint32_t idx)
17:void FUNC1(uint32_t idx)
23:void FUNC2(uint32_t idx)
28:void FUNC3(uint32_t idx)
```

若行号不符（文件被额外空行干扰），以 grep 实际输出为准修正 Step 3 的 JSON。

- [ ] **Step 3: 创建树输入 ef4ebf80.json**

```json
{
    "FUNC0$ef4ebf80": [
        [
            {"func": "FUNC0", "file": "test_fixtures/tree_test/test.c", "begin_line": "8"},
            {"func": "FUNC1", "file": "test_fixtures/tree_test/test.c", "begin_line": "17"},
            {"func": "FUNC2", "file": "test_fixtures/tree_test/test.c", "begin_line": "23"}
        ],
        [
            {"func": "FUNC0", "file": "test_fixtures/tree_test/test.c", "begin_line": "8"},
            {"func": "FUNC3", "file": "test_fixtures/tree_test/test.c", "begin_line": "28"}
        ]
    ]
}
```

- [ ] **Step 4: 校验 JSON 合法**

```bash
python3 -m json.tool test_fixtures/tree_test/ef4ebf80.json > /dev/null && echo "VALID JSON"
```

Expected: `VALID JSON`

- [ ] **Step 5: 提交**

```bash
git add test_fixtures/tree_test/test.c test_fixtures/tree_test/ef4ebf80.json
git commit -m "test: add tree_test fixture with two-chain call tree"
```

---

### Task 10: 主流程端到端试跑

**Files:**
- Verify: `test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md`（运行产物，不入库）

- [ ] **Step 1: 确认 claude CLI 可用**

```bash
which claude
```

Expected: 输出 claude 可执行路径（如 `/usr/local/bin/claude` 或 npm 全局路径）。

- [ ] **Step 2: 在新会话中运行 skill**（`-p` 为无交互打印模式；新会话会重新发现 .claude/skills 下新注册的 skill。命令在仓库根目录执行，耗时可能数分钟，timeout 设 600000ms）

```bash
cd /home/admin/cc/wksp/siakam_security_skills/taint_path_checker && claude -p "/taint-tree-checker test_fixtures/tree_test test_fixtures/tree_test/ef4ebf80.json" --dangerously-skip-permissions
```

Expected: 命令正常结束，无报错。

- [ ] **Step 3: 断言报告文件存在**

```bash
ls test_fixtures/tree_test/.ethunter_out/taint-tree-checker/
```

Expected: 存在 `ef4ebf80_result.md`。

- [ ] **Step 4: 断言报告内容**

```bash
grep -n "调用树ID\|结论\|漏洞ID\|TAINT-" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md
```

Expected 要点：
- `调用树ID`：`ef4ebf80`
- `结论`：`发现 1 个安全漏洞`（链2 FUNC3 已校验，且 `g_flag` 链间不传播——链2 不应报漏洞，验证链间独立）
- 恰好一个 `TAINT-xxxxxxxx`，其"所在函数"为 `FUNC2`，"关键行号"含 `25`（哈希应为 `/绝对路径/test.c:FUNC2:23` 的 SHA256 前 8 位）

```bash
grep -n "FUNC3" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md
```

Expected: 仅出现在攻击路径或分析情况简述之外不构成漏洞（即不存在以 FUNC3 为"所在函数"的漏洞记录）。

- [ ] **Step 5: 断言攻击路径格式符合下游要求**

Read 报告中攻击路径段落，确认格式为 `[N] 文件:行号 函数名()` 链式记录，末步标注 `← 触发点`，路径为 FUNC0 → FUNC1 → FUNC2。

- [ ] **Step 6: 本任务无代码变更，无需提交**（报告产物已被 gitignore）。若 Step 4/5 断言失败，回到对应 SKILL.md 章节修复并提交 fix，再重跑本任务。

---

### Task 11: 预查重与异常分支试跑

**Files:**
- Verify: `test_fixtures/tree_test/.ethunter_out/taint-tree-checker/`（运行产物）
- Create then delete: `test_fixtures/tree_test/mismatch.json`、`test_fixtures/tree_test/missing.json`（临时负面夹具，验证后清理）

- [ ] **Step 1: 预查重验证**（重跑主流程，应跳过）

```bash
cd /home/admin/cc/wksp/siakam_security_skills/taint_path_checker && claude -p "/taint-tree-checker test_fixtures/tree_test test_fixtures/tree_test/ef4ebf80.json" --dangerously-skip-permissions 2>&1 | grep -o "该调用树已有分析结果[^\"]*"
```

Expected: 输出包含 `该调用树已有分析结果：...ef4ebf80_result.md，跳过分析。`

- [ ] **Step 2: TreeID 不一致分支**（创建临时负面夹具）

```bash
cat > test_fixtures/tree_test/mismatch.json <<'EOF'
{
    "FUNC0$deadbeef": [
        [
            {"func": "FUNC0", "file": "test_fixtures/tree_test/test.c", "begin_line": "8"},
            {"func": "FUNC2", "file": "test_fixtures/tree_test/test.c", "begin_line": "23"}
        ]
    ]
}
EOF
claude -p "/taint-tree-checker test_fixtures/tree_test test_fixtures/tree_test/mismatch.json" --dangerously-skip-permissions
```

Expected: 生成 `mismatch_result.md`，内容含报错（TreeID 与文件名不一致）且未做漏洞分析（无 TAINT- 条目）。

```bash
grep -c "TAINT-" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/mismatch_result.md
```

Expected: `0`

- [ ] **Step 3: 某链源码缺失分支**（链2 引用不存在的函数）

```bash
cat > test_fixtures/tree_test/missing.json <<'EOF'
{
    "FUNC0$missing": [
        [
            {"func": "FUNC0", "file": "test_fixtures/tree_test/test.c", "begin_line": "8"},
            {"func": "FUNC1", "file": "test_fixtures/tree_test/test.c", "begin_line": "17"},
            {"func": "FUNC2", "file": "test_fixtures/tree_test/test.c", "begin_line": "23"}
        ],
        [
            {"func": "FUNC0", "file": "test_fixtures/tree_test/test.c", "begin_line": "8"},
            {"func": "GHOST", "file": "test_fixtures/tree_test/no_such_file.c", "begin_line": "1"}
        ]
    ]
}
EOF
claude -p "/taint-tree-checker test_fixtures/tree_test test_fixtures/tree_test/missing.json" --dangerously-skip-permissions
```

Expected: 生成 `missing_result.md`；报告基于链1 正常分析（含 FUNC2 的漏洞），摘要中注明链2 因 GHOST 源码未找到被跳过。

```bash
grep -n "跳过" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/missing_result.md
```

Expected: 有匹配（注明链2 被跳过）。

- [ ] **Step 4: 清理临时负面夹具与产物**

```bash
rm test_fixtures/tree_test/mismatch.json test_fixtures/tree_test/missing.json
rm -rf test_fixtures/tree_test/.ethunter_out/taint-tree-checker/mismatch_result.md test_fixtures/tree_test/.ethunter_out/taint-tree-checker/missing_result.md
git status --short
```

Expected: 仅显示（如存在）未跟踪的 .ethunter_out 目录（已被 gitignore，可忽略）；无 mismatch/missing 残留。

- [ ] **Step 5: 本任务无代码变更，无需提交**。

---

### Task 12: 下游 taint-path-cleaner 兼容性试跑

**Files:**
- Verify: `test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-{id}.md`（运行产物）

- [ ] **Step 1: 用现有 cleaner 消费树报告**（cleaner 零改动）

```bash
cd /home/admin/cc/wksp/siakam_security_skills/taint_path_checker && claude -p "/taint-path-cleaner test_fixtures/tree_test test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md" --dangerously-skip-permissions
```

Expected: 命令正常结束。

- [ ] **Step 2: 断言 cleaner 判定结果**

```bash
ls test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/ test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/FPs/ 2>/dev/null
grep -n "判定结果" test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-*.md
```

Expected: `Vulns/TAINT-{id}.md` 存在且 `判定结果：正报`（FUNC2 中 `g_buf[idx]` 无校验，属真实越界写）。

- [ ] **Step 3: 回归确认旧 skill 未受影响**

```bash
git status --short
git log --oneline -15
```

Expected: 工作区除 gitignore 的 .ethunter_out 外干净；提交历史包含本计划的各 feat 提交，且无对 taint-path-checker / taint-path-cleaner 的修改提交。

- [ ] **Step 4: 本任务无代码变更，无需提交**。若 Step 2 断言失败（如 cleaner 无法解析树报告），检查报告字段是否与下游要求一致，修复后重跑 Task 10-12。
