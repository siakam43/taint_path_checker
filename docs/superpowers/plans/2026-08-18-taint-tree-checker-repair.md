# taint-tree-checker 修复与优化 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修订 taint-tree-checker/SKILL.md——引入四阶段 sink 优先分析流程、全树共享全局污点语义（跨调用前提）、污点驱动的调用树修复与落盘，并补齐测试夹具验证。

**Architecture:** 单一 markdown skill 文档修订，按章节分组小步提交；验证方式为两个测试夹具（复用 tree_test 验证新污点语义、新增 tree_repair 验证树修复与落盘），通过实际调用 skill 试跑并断言输出。

**Tech Stack:** Markdown skill 文档、JSON 夹具、bash/grep/python3 验证命令。

**Spec:** `docs/superpowers/specs/2026-08-18-taint-tree-checker-repair-design.md`

---

### Task 1: 修订二、三章（输出目录说明 + 源码缺失规则）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（2.3、三.3/三.4）

- [ ] **Step 1: 2.3 新增修复树落盘说明**

Edit（old_string 唯一锚点：`目录不存在则使用 \`mkdir -p\` 创建。`，位于 2.3 节）：

```
old: 目录不存在则使用 `mkdir -p` 创建。
new: 目录不存在则使用 `mkdir -p` 创建。分析过程中修复后的调用树写入同目录 `{TreeID}_tree_fixed.json`。
```

- [ ] **Step 2: 三.3/三.4 重写源码缺失与树外函数规则**

Edit（old_string 为当前三.3、三.4 两行全文）：

```
old:
3. 若某函数源码在给定文件中不存在，**跳过该函数**，在最终报告中注明。不得因个别函数缺失而中止整棵树的分析。
4. 对于树外辅助函数：当污点数据传递到当前树之外的函数时，需在 project_dir 中搜索该函数的定义并分析其对污点数据的操作。但漏洞判定仍回归树内。

new:
3. 若某函数源码在给定文件中不存在：该函数**可能接收污点**（参数为污点或读取已污染的全局/静态变量；无法确认时按可能接收处理）→ 该链污点状态未知，跳过该链、其余链照常分析，摘要注明"函数 xxx 源码未找到，跳过该链"；**可确认不接触污点**（仅常量参数、不读取污点全局变量）→ 继续该链分析，摘要注明"函数 xxx 源码未找到，其不接触污点数据，分析继续"。不得因个别函数缺失而中止整棵树的分析。
4. 对于树外辅助函数：当污点数据传递到当前树之外的函数时，需在 project_dir 中搜索该函数的定义并分析其对污点数据的操作，并按 4.3 决定是否将其补入调用树。
```

- [ ] **Step 3: 回读校验**

Run: `git diff taint-tree-checker/SKILL.md`
Expected: 仅上述两处变更；三.3 不再出现"跳过该函数"字样。

- [ ] **Step 4: Commit**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "fix: unify missing-source rule and add fixed-tree output note in taint-tree-checker"
```

---

### Task 2: 修订四章 4.1/4.2（全树共享全局污点语义）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（4.1 末尾、4.2(3) 表）

- [ ] **Step 1: 4.1 末尾新增全局污点全树共享规则段**

Edit（old_string 为 4.1 最后一个列表项，锚点唯一）：

```
old: - 通过内核 API 获取的内部状态指针

new: - 通过内核 API 获取的内部状态指针

**全局/静态变量污点全树共享**：污点写入全局/静态变量后，调用树内任何后续函数（包括其他链中的函数）读取时视为污点。堆、共享内存（shm、dma_buf）等持久存储同规则。

- **同链内**：写入与读取在同一链中，单次调用即可触发，攻击路径无需额外说明。
- **跨链**：写入在一条链、读取在另一条链，攻击路径必须写明**多次调用**触发序列（如"第一次调用沿链1设置 g_var，第二次调用沿链2触发"）。
- **失效条件**：入口函数或其每次调用的必经路径重置/初始化该全局时，不可跨调用传播。
```

- [ ] **Step 2: 4.2(3) 全局变量表三行改为树级语义**

Edit（old_string 为 4.2(3) 整表）：

```
old:
| 模式 | 示例 | 规则 |
|------|------|------|
| 全局变量写入 | `g_var = tainted;` | 污点写入全局变量，后续函数读取 g_var 时视为污点 |
| 静态局部变量 | `static int s = tainted;` | 同全局变量，s 在链内后续函数调用中保持污点 |
| 全局变量读取 | `local = g_var;` | 若链内前面的函数已污染 g_var，则 local 为污点 |

new:
| 模式 | 示例 | 规则 |
|------|------|------|
| 全局变量写入 | `g_var = tainted;` | 污点写入全局变量，调用树内后续函数读取 g_var 时视为污点（跨链规则见 4.1） |
| 静态局部变量 | `static int s = tainted;` | 同全局变量，s 在调用树内后续函数调用中保持污点 |
| 全局变量读取 | `local = g_var;` | 若调用树内前面的函数已污染 g_var，则 local 为污点 |
```

- [ ] **Step 3: 回读校验**

Run: `git diff taint-tree-checker/SKILL.md`
Expected: 4.2 表中不再有"链内"字样；4.1 新增规则段与 spec 决策 1 一致。

- [ ] **Step 4: Commit**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: define cross-chain global taint sharing with multi-invocation premise"
```

---

### Task 3: 重写 4.3 数据流构建 + 4.4 注意事项

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（4.3、4.4 整节）

- [ ] **Step 1: 4.3 整节替换**

Edit（old_string 为当前 4.3 整节，从 `### 4.3 污点传播数据流构建` 到 `用于后面的"危险使用点与校验检查"。`）：

```
old:
### 4.3 污点传播数据流构建

以入口函数为起点，依次沿着调用树中的每一条调用链（仅包含函数调用关系）进行污点传播的数据流追踪，构建出一条条准确的污点传播数据流路线（包含污点数据在不同变量和函数间的传递过程）。

在污点传播追踪过程中，注意修复调用树中可能包含的错误：

- **调用链缺失**：发现污点数据被传播到调用树之外的函数形成新的分支，新的调用链没有包含在原调用树内。请将新调用链补充进调用树。
- **调用链提前中断**：发现污点数据传播到链尾后仍在继续传播，原调用链由于间接调用等原因意外中断。请将原调用链补充完整。

基于修复完整的调用树中的每一条调用链，输出准确的污点传播数据流路线，用于后面的"危险使用点与校验检查"。

new:
### 4.3 污点传播数据流构建

本阶段是全部分析的质量核心：数据流不完整则后续判定全部失真。以入口函数为起点，沿调用树追踪污点传播，**过程中修复调用树**，产出完整准确的污点数据流路线集合（包含污点数据在不同变量和函数间的传递过程）。遍历方式不做强制（逐链或广度优先均可），但必须覆盖污点可达的全部代码。

**调用树修复规则：**

- **仅污点驱动**：只记录污点数据实际传播到的调用关系。函数 a 调用 b 但未将污点传给 b 时，a→b 不补入树，防止路径爆炸。
- **调用链缺失**：污点传播到树外函数并继续形成新分支 → 从入口函数起补写完整新链。
- **调用链提前中断**：污点传播到链尾后仍在继续传播（间接调用等原因）→ 延伸该链直至污点停止传播或到达危险使用点。
- **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数；无法确定目标时该分支标注"无法追踪"并停止延伸，不臆造。
- **落盘**：修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致。不得修改输入文件。

**完整性自检（本阶段结束前强制执行）**：每个污点变量必须追踪到以下四态之一——停止传播（不再传递）、被无害消费（使用但无危险模式）、被净化（校验后）、到达危险使用点。存在未达四态之一的污点变量时，不得进入第五章的危险使用扫描。
```

- [ ] **Step 2: 4.4 整节替换**

Edit（old_string 为当前 4.4 整节六个列表项）：

```
old:
### 4.4 追踪注意事项

- **同名变量区分**：分析代码上下文，结合作用域和数据流，区分同名不同作用域的变量。
- **结构体成员区分**：结构体整体为污点则全部成员为污点；若污点数据赋值给某成员，则仅该成员为污点。
- **树外函数追踪**：污点传递到调用树外函数时，查找该函数定义，分析其对污点的操作（污染了哪些新变量、是否有校验），修复调用树，然后回到调用树内继续追踪。
- **别名分析**：同一内存地址通过不同指针访问时，任一路径的污点写入影响所有别名。
- **全局/静态变量追踪**：污点在树内某函数写入全局或静态变量后，后续函数读取该变量时视为污点传播，直到被覆盖或显式净化。
- **状态跟踪**：跨函数追踪时维护变量污点状态（变量名、位置、状态、来源、校验），到达危险使用点前回溯确认无遗漏。

new:
### 4.4 追踪注意事项

- **同名变量区分**：分析代码上下文，结合作用域和数据流，区分同名不同作用域的变量。
- **结构体成员区分**：结构体整体为污点则全部成员为污点；若污点数据赋值给某成员，则仅该成员为污点。
- **树外函数追踪**：污点传递到树外函数时，查找该函数定义，分析其对污点的操作（污染了哪些新变量、是否有校验）。污点在该函数内继续传播到新的树外函数时，按 4.3 调用链缺失/中断规则修复调用树；污点在该函数内停止（被消费或净化）时不补入树。
- **别名分析**：同一内存地址通过不同指针访问时，任一路径的污点写入影响所有别名。
- **全局/静态变量追踪**：污点在树内某函数写入全局或静态变量后，调用树内后续函数读取该变量时视为污点传播，直到被覆盖或显式净化（跨链规则见 4.1）。
- **状态跟踪**：跨函数追踪时维护变量污点状态（变量名、位置、状态、来源、校验），到达危险使用点前回溯确认无遗漏。
```

- [ ] **Step 3: 回读校验**

Run: `git diff taint-tree-checker/SKILL.md`
Expected: 4.3 含"仅污点驱动"、"落盘"、"四态"三处新增；4.4 树外函数追踪与 4.3 联动。

- [ ] **Step 4: Commit**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: rewrite dataflow-build stage with taint-driven tree repair and completeness gate"
```

---

### Task 4: 修订六章门禁（跨调用触发前提）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（六.1）

- [ ] **Step 1: 六.1"可触发"补充跨调用前提**

Edit（old_string 为当前六.1 全文）：

```
old: 1. **可触发**：该漏洞是否可以从入口函数的外部输入触发？请描述完整的触发路径（自入口参数开始，经过哪些变量传递，最终到达漏洞点）。若漏洞代码路径受预处理宏条件控制，须结合源码中的宏定义及已加载的编译宏配置综合判断。

new: 1. **可触发**：该漏洞是否可以从入口函数的外部输入触发？请描述完整的触发路径（自入口参数开始，经过哪些变量传递，最终到达漏洞点）。跨链全局污点触发的漏洞，攻击路径须写明多次调用触发序列（见 4.1）。若漏洞代码路径受预处理宏条件控制，须结合源码中的宏定义及已加载的编译宏配置综合判断。
```

- [ ] **Step 2: 回读校验**

Run: `git diff taint-tree-checker/SKILL.md`
Expected: 仅六.1 一处变更。

- [ ] **Step 3: Commit**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: require multi-invocation trigger sequence in reachability gate"
```

---

### Task 5: 修订七、八、九章（模板、检查清单、陷阱、边缘情况）

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（7.3、7.4、7.5 标题、八、9.1、9.2）

- [ ] **Step 1: 7.3 无漏洞模板摘要增加各链覆盖结论**

Edit（old_string 为 7.3 摘要段）：

```
old:
## 分析摘要

（简述调用树功能、调用树修复情况、污点数据追踪结果、关键校验点说明）

该调用树的外部输入在各条调用链传播过程中，均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。

new:
## 分析摘要

（简述调用树功能、调用树修复情况——补充/延伸了哪些链或"未修复"、污点数据追踪结果、关键校验点说明）

**各链覆盖结论**：

- 链1（FUNC0 → ...）：已纳入数据流追踪 / 跳过（注明原因）
- 链2（FUNC0 → ...）：已纳入数据流追踪 / 跳过（注明原因）

该调用树的外部输入在各条调用链传播过程中，均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。
```

- [ ] **Step 2: 7.4 有漏洞模板恢复"分析情况"小节**

Edit（old_string 为 7.4 头部结论行到漏洞列表标题之间）：

```
old:
- **结论**：发现 N 个安全漏洞

## 漏洞列表

new:
- **结论**：发现 N 个安全漏洞

## 分析情况

（调用树共含 M 条链；各链覆盖结论：已纳入数据流追踪/跳过及原因；调用树修复情况：补充/延伸了哪些链或"未修复"）

## 漏洞列表
```

- [ ] **Step 3: 7.5 标题改"树外漏洞标记"**

Edit：`old: ### 7.5 链外漏洞标记` → `new: ### 7.5 树外漏洞标记`（字段名"是否链外"与字段值**不得改动**——下游 cleaner 解析依赖）。

- [ ] **Step 4: 八、检查清单更新**

Edit（old_string 为当前检查清单 7 项）：

```
old:
1. 输出文件 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 是否存在。
2. 调用树内每条链是否都有结论（已分析或已跳过，跳过的注明原因）。
3. 报告的结论（有漏洞/无漏洞）是否有充分的分析依据。
4. 每个上报的漏洞是否通过了硬性检查门的三问。
5. 漏洞 ID 是否基于 file:func:line 正确生成，树内同 ID 漏洞是否已合并。
6. 是否有排除清单中的问题类型被误报。

new:
1. 输出文件 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_result.md` 是否存在。
2. 调用树内每条链是否有覆盖结论（已纳入数据流追踪/跳过，跳过的注明原因）。
3. 有树修复时 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json` 是否写出。
4. 报告的结论（有漏洞/无漏洞）是否有充分的分析依据。
5. 每个上报的漏洞是否通过了硬性检查门的三问。
6. 漏洞 ID 是否基于 file:func:line 正确生成，树内同 ID 漏洞是否已合并。
7. 是否有排除清单中的问题类型被误报。
```

- [ ] **Step 5: 9.1 思维陷阱新增跨链陷阱行**

Edit（在"分析太长了，后面简化一下"行后插入新行）：

```
old: | "分析太长了，后面简化一下" | 宁可多花时间确保准确，牺牲效率保证质量 |

new: | "分析太长了，后面简化一下" | 宁可多花时间确保准确，牺牲效率保证质量 |
     | "链1写入的全局变量链2读取，直接当污点报" | 跨链读取全局污点必须写明多次调用触发序列；入口函数每次调用重置该全局时不可传播（见 4.1） |
```

- [ ] **Step 6: 9.2 边缘情况表更新**

Edit（old_string 为 9.2 表前两行）：

```
old:
| 调用树中某函数源码找不到 | 跳过该函数，继续分析调用树中其它调用链，在摘要中注明该调用链的分析结论："函数 xxx 源码未找到，跳过该链" |
| 某链污点传播路径在某处无法追踪 | 跳过该链，其余链照常分析，在摘要中注明"变量A在函数B中污点状态无法确定" |

new:
| 调用树中某函数源码找不到 | 可能接收污点（无法确认按可能接收处理）→ 跳过该链，其余链照常，摘要注明"函数 xxx 源码未找到，跳过该链"；确认不接触污点 → 继续该链，摘要注明 |
| 某链污点传播路径在某处无法追踪 | 跳过该链，其余链照常分析，在摘要中注明"变量A在函数B中污点状态无法确定" |
| 间接调用无法确定目标函数 | 该分支标注"无法追踪"并停止延伸，不臆造目标 |
```

- [ ] **Step 7: 回读校验**

Run: `git diff taint-tree-checker/SKILL.md`
Expected: 七/八/九章共 6 处变更；`grep -c "是否链外"` 输出 ≥2（字段名保留）。

- [ ] **Step 8: Commit**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "feat: align report templates, checklist, and edge cases with coverage and tree-repair model"
```

---

### Task 6: 新建 tree_repair 测试夹具

**Files:**
- Create: `test_fixtures/tree_repair/test.c`
- Create: `test_fixtures/tree_repair/repair01.json`

夹具设计：输入树只有一条链 `func_dispatch → func_branch_a`，且被间接调用截断。真实代码中：(1) `func_branch_a` 经函数指针 `g_cb` 调用 `func_indirect`（链中断，需延伸）；(2) `cmd != 0` 分支进入 `func_branch_b`（树外分支，污点可达，需补链）；(3) `func_branch_b` 调用 `func_helper(0)` 传常量（非污点调用关系，**不得**补入树）。

- [ ] **Step 1: 创建 test.c（行号即函数 begin_line，勿改动格式）**

```c
#include <stdint.h>

#define BUF_SIZE 16

static uint8_t g_buf[BUF_SIZE];
static void (*g_cb)(uint32_t);

void func_dispatch(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {
        func_branch_a(idx);
    } else {
        func_branch_b(idx);
    }
}

void func_branch_a(uint32_t idx)
{
    g_cb = func_indirect;
    g_cb(idx);
}

void func_indirect(uint32_t idx)
{
    g_buf[idx] = 0x55;
}

void func_branch_b(uint32_t idx)
{
    func_helper(0);
    if (idx < BUF_SIZE)
        g_buf[idx] = 0xAA;
}

void func_helper(uint32_t x)
{
    (void)x;
}
```

begin_line 参考：func_dispatch=8、func_branch_a=17、func_indirect=23、func_branch_b=28。

- [ ] **Step 2: 创建 repair01.json（文件路径遵循既有夹具的相对路径约定）**

```json
{
    "func_dispatch$repair01": [
        [
            {"func": "func_dispatch", "file": "test_fixtures/tree_repair/test.c", "begin_line": "8"},
            {"func": "func_branch_a", "file": "test_fixtures/tree_repair/test.c", "begin_line": "17"}
        ]
    ]
}
```

- [ ] **Step 3: 验证 JSON 合法与行号正确**

Run: `python3 -m json.tool test_fixtures/tree_repair/repair01.json > /dev/null && grep -n "^void func_" test_fixtures/tree_repair/test.c`
Expected: JSON 无报错；grep 输出 func_dispatch:8、func_branch_a:17、func_indirect:23、func_branch_b:28。若行号不符，修正 JSON 的 begin_line（勿改 test.c 行号）。

- [ ] **Step 4: Commit**

```bash
git add test_fixtures/tree_repair/test.c test_fixtures/tree_repair/repair01.json
git commit -m "test: add tree_repair fixture with truncated chain and missing branch"
```

---

### Task 7: 全文件一致性自检

**Files:**
- Modify: `taint-tree-checker/SKILL.md`（仅当自检发现问题时）

- [ ] **Step 1: 残留单链措辞扫描**

Run: `grep -n "链内" taint-tree-checker/SKILL.md; grep -n "逐链" taint-tree-checker/SKILL.md`
Expected: `链内` 无匹配（退出码 1）；`逐链` 仅出现在 4.3"遍历方式不做强制（逐链或广度优先均可）"一处。若发现其他残留，按语义改为"调用树内/各链"并记录。

- [ ] **Step 2: 术语一致性扫描**

Run: `grep -n "链外" taint-tree-checker/SKILL.md`
Expected: 仅剩字段名"是否链外"（7.4 模板字段行、7.5 正文"标注"是否链外：是""）。其余位置均应为"树外/调用树外"。

- [ ] **Step 3: spec 覆盖核对**

通读 `taint-tree-checker/SKILL.md` 全文，对照 spec 逐章修改设计核对：二.3 落盘说明、三.3 源码缺失规则、4.1 全树共享、4.2(3) 树级措辞、4.3 修复规则+四态自检、4.4 联动、六.1 跨调用前提、7.3/7.4 覆盖结论与修复情况、7.5 标题、八.2/八.3、9.1 跨链陷阱、9.2 三行。任一缺失则补上。

- [ ] **Step 4: Commit（仅当有修改时）**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "fix: consistency cleanup after tree-model revision"
```

---

### Task 8: 试跑 tree_test 夹具验证新语义

**Files:**
- Modify: `test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md`（重新生成的新基线）

背景：新语义下 `FUNC1`（链1）写入 `g_flag = idx`，`FUNC3`（链2）`g_buf[g_flag]` 未校验 g_flag → 新增第二个漏洞（跨调用触发：第一次调用 cmd=0 设置 g_flag，第二次调用 cmd=1 触发）。旧基线只报了 FUNC2 一个漏洞。

- [ ] **Step 1: 备份旧基线结果（预查重会跳过已存在的文件）**

Run: `mv test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md /tmp/ef4ebf80_result.md.bak`

- [ ] **Step 2: 调用 skill 试跑**

在仓库根目录调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_test test_fixtures/tree_test/ef4ebf80.json`。（若执行环境不支持 Skill 工具，改为逐节遵循 SKILL.md 指令手工执行分析。）

- [ ] **Step 3: 断言结果文件**

Run: `ls test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md && grep -c "TAINT-" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md`
Expected: 文件存在；TAINT- 出现次数 ≥4（两个漏洞各 2 处：列表标题+字段表）。

- [ ] **Step 4: 断言 FUNC3 跨调用漏洞与攻击路径**

Run: `grep -n "FUNC3" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md | head -5 && grep -n "第一次调用\|第二次调用" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md`
Expected: 漏洞列表含所在函数 FUNC3（关键行号 32）的漏洞；其攻击路径/原理中出现"第一次调用"与"第二次调用"的多次调用序列描述。

- [ ] **Step 5: 断言漏洞 ID 规则**

Run: `echo -n "$(pwd)/test_fixtures/tree_test/test.c:FUNC3:32" | sha256sum | cut -c1-8`
Expected: 输出值与报告中 FUNC3 漏洞的 TAINT-xxxxxxxx 后缀一致（FUNC2 漏洞 ID 同理，用 `:FUNC2:25` 验证）。

- [ ] **Step 6: 断言修复情况**

Run: `grep -n "修复" test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md`
Expected: 分析情况/摘要中说明"未修复"（输入树已完整）。

- [ ] **Step 7: Commit 新基线**

```bash
git add test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md
git commit -m "test: update tree_test baseline for cross-chain taint semantics (2 vulns)"
```

注意：夹具中 `taint-path-cleaner/` 旧产物不动（本次未重跑 cleaner）；若断言失败，从 `/tmp/ef4ebf80_result.md.bak` 恢复旧基线并修复 skill 后重试。

---

### Task 9: 试跑 tree_repair 夹具验证树修复与落盘

**Files:**
- Create: `test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md`
- Create: `test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_tree_fixed.json`

- [ ] **Step 1: 调用 skill 试跑**

在仓库根目录调用 Skill 工具：skill=`taint-tree-checker`，args=`test_fixtures/tree_repair test_fixtures/tree_repair/repair01.json`。

- [ ] **Step 2: 断言修复树落盘与内容**

Run: `python3 - <<'EOF'
import json
with open("test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_tree_fixed.json") as f:
    data = json.load(f)
chains = data["func_dispatch$repair01"]
funcs = [[e["func"] for e in c] for c in chains]
assert ["func_dispatch","func_branch_a","func_indirect"] in funcs, funcs
assert ["func_dispatch","func_branch_b"] in funcs, funcs
assert len(chains) == 2, funcs
for c in chains:
    for e in c:
        assert e["func"] != "func_helper", "非污点调用关系不得补入树"
print("OK:", funcs)
EOF`
Expected: 输出 `OK: [['func_dispatch', 'func_branch_a', 'func_indirect'], ['func_dispatch', 'func_branch_b']]`。

- [ ] **Step 3: 断言报告**

Run: `grep -n "修复\|func_indirect" test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_result.md | head -10`
Expected: 结论为发现 1 个漏洞（func_indirect 第 25 行 `g_buf[idx] = 0x55` 未校验）；分析情况说明修复内容（延伸链1至 func_indirect、补充 func_branch_b 链）；func_branch_b 不报漏洞（已校验）。

- [ ] **Step 4: 断言输入文件未被修改**

Run: `git status --short test_fixtures/tree_repair/repair01.json`
Expected: 无输出（输入 JSON 未被改动）。

- [ ] **Step 5: Commit 输出**

```bash
git add test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/
git commit -m "test: record tree_repair run output with fixed tree artifact"
```

---

### Task 10: 收尾回归

**Files:**
- 无修改（仅检查）

- [ ] **Step 1: 确认其他 skill 未受影响**

Run: `git diff HEAD~10 --stat -- taint-path-checker/ taint-path-cleaner/`
Expected: 空（本计划未触碰两个既有 skill）。

- [ ] **Step 2: 最终全文通读**

通读 `taint-tree-checker/SKILL.md` 全文一遍，确认无矛盾、无半截修改。

- [ ] **Step 3: 汇总提交记录**

Run: `git log --oneline -12`
Expected: 本计划 10 个左右的原子提交，均以 fix:/feat:/test:/docs: 开头。
