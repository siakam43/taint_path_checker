# taint 系列 skill 路径相对化 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 taint-tree-checker / taint-path-checker / taint-path-cleaner 三个 SKILL.md 的路径处理统一为相对 `<project_dir>` 的规范化相对路径（输入解析、报告展示、漏洞哈希），并同步更新 fixture 期望报告。

**Architecture:** 纯文档改造，无代码。两个 checker 各自新增逐字一致的"2.6 路径规范"小节（规范化 norm + file 字段转换规则），修改 2.2/三/7.1/7.4/检查清单中的路径措辞；cleaner 仅在 4.1 定位源码处补充相对路径解析规则。fixture 期望报告用一次性 Python 脚本做机械变换（绝对前缀剥离、代码片段注释相对化、漏洞 ID 按新哈希公式替换）。

**Tech Stack:** Markdown 文档编辑；验证用 bash（grep、diff、sha256sum）与一次性 Python3 脚本。

**前置约定（本计划全篇使用）：**
- `P` = `/home/admin/cc/wksp/siakam_security_skills/taint_path_checker`（仓库根，即 project_dir）
- 新哈希公式：`hash8 = sha256("{rel}:{函数名}:{起始行号}")[:8]`，rel 为规范化相对路径，起始行号为报告"关键行号"字段的起始行
- 两个 checker 的 2.6 小节必须逐字一致（见 Task 7 验证）
- skill 正文不得出现"新格式/旧格式"等变动历史措辞

---

### Task 1: taint-tree-checker/SKILL.md 路径规范改造

**Files:**
- Modify: `taint-tree-checker/SKILL.md`

- [ ] **Step 1: 修改 2.2 JSON 示例中的 file 路径**

用 Edit 工具 `replace_all`：
- old: `"file": "/src/a.c"` → new: `"file": "src/a.c"`（共 4 处）

- [ ] **Step 2: 修改 2.2 字段表格**

Edit：
- old: `| \`file\` | string | 函数所在源文件的绝对路径 |`
- new: `| \`file\` | string | 函数所在源文件路径，相对 \`<project_dir>\` |`

- [ ] **Step 3: 解析规则新增第 5 条**

Edit：
- old:
```
4. **链数组非空**：链数组必须为非空数组，否则在报告中报错并结束本次任务。
```
- new:
```
4. **链数组非空**：链数组必须为非空数组，否则在报告中报错并结束本次任务。
5. **file 字段路径**：每个链元素的 `file` 按 2.6 路径规范转换，转换失败（绝对路径不在 project_dir 内、规范化后含 `..` 段）在报告中报错并结束本次任务。
```

- [ ] **Step 4: 新增 2.6 路径规范小节**（插在 2.5 与"## 三"之间）

Edit（用包含 2.5 结尾句的长串保证唯一）：
- old:
```
检查 `{project_dir}/.ethunter_out/macro.json` 是否存在。若存在，读取并记住其中的宏定义（格式 `{"MACRO": "value", ...}`），这些是编译指令中动态定义的宏。若不存在则跳过，后续照常分析。

---

## 三、获取目标代码
```
- new:
```
检查 `{project_dir}/.ethunter_out/macro.json` 是否存在。若存在，读取并记住其中的宏定义（格式 `{"MACRO": "value", ...}`），这些是编译指令中动态定义的宏。若不存在则跳过，后续照常分析。

### 2.6 路径规范

- **规范化 norm(p)**：分隔符统一为 `/`；去掉前导 `./`（连续重复一并去掉）。规范化后含 `..` 段的路径非法（无法保证位于 project_dir 内），按解析规则报错并结束本次任务。
- **file 字段转换**：`file` 为相对路径时，norm 后直接使用；为绝对路径时，若以 `norm(project_dir)` 为前缀，去掉该前缀得相对路径；否则报错并结束本次任务。
- 转换得到的规范化相对路径（下称 rel）用于定位源码（`{project_dir}/{rel}`）、计算漏洞哈希（见 7.1）与报告展示（见 7.4）。

---

## 三、获取目标代码
```

- [ ] **Step 5: 修改"三、获取目标代码"第 1 步**

Edit：
- old: `1. 根据 \`file\` 和 \`begin_line\` 定位函数定义。`
- new: `1. 按 2.6 将 \`file\` 转换为 rel，以 \`{project_dir}/{rel}\` 定位函数定义并读取。`

- [ ] **Step 6: 修改 4.3.1 落盘规则**

Edit：
- old: `- **落盘**：有修复时，将修复后的调用树写入 \`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json\`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。`
- new: `- **落盘**：有修复时，将修复后的调用树写入 \`{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json\`，格式与输入 JSON 一致（file 字段使用规范化相对路径）；未修复则不生成该文件。不得修改输入文件。`

- [ ] **Step 7: 修改 7.1 漏洞 ID 生成**

Edit：
- old:
```
其中 `hash8` = 对字符串 `{文件绝对路径}:{函数名}:{起始行号}` 计算 SHA256，取前 8 位十六进制字符。**起始行号为漏洞关键行号的起始行**（与 7.4 模板的关键行号字段一致），不是函数定义行。

在 bash 中执行（示例）：
```bash
echo -n "/srv/code/driver.c:npu_sem_alloc:380" | sha256sum | cut -c1-8
```
```
- new:
```
其中 `hash8` = 对字符串 `{rel}:{函数名}:{起始行号}` 计算 SHA256，取前 8 位十六进制字符。rel 为按 2.6 转换得到的规范化相对路径。**起始行号为漏洞关键行号的起始行**（与 7.4 模板的关键行号字段一致），不是函数定义行。

在 bash 中执行（示例）：
```bash
echo -n "src/driver.c:npu_sem_alloc:380" | sha256sum | cut -c1-8
```
```

- [ ] **Step 8: 修改 7.4 模板"所在文件"**

Edit：
- old: `| **所在文件** | /绝对路径/file.c |`
- new: `| **所在文件** | src/file.c |`

- [ ] **Step 9: 修改 7.4 攻击路径示例**

Edit：
- old:
```
[1] /绝对路径/file_a.c:111  func_entry()
[2]   :49                    func_dispatch()
[3]   :230                   func_process()
[4] /绝对路径/file_b.c:78    func_trigger()  ← 触发点
```
- new:
```
[1] src/file_a.c:111  func_entry()
[2]   :49             func_dispatch()
[3]   :230            func_process()
[4] src/file_b.c:78   func_trigger()  ← 触发点
```

- [ ] **Step 10: 修改 7.4 攻击路径格式规则**

Edit：
- old: `- \`文件:行号  函数名()\`。同文件连续时后续步骤只写 \`:行号\`；跨文件时补全 \`/绝对路径/file.c:行号\`。`
- new: `- \`文件:行号  函数名()\`。同文件连续时后续步骤只写 \`:行号\`；跨文件时补全规范化相对路径 \`src/file.c:行号\`。`

- [ ] **Step 11: 修改检查清单第 6 条**

Edit：
- old: `6. 漏洞 ID 是否基于 file:func:line 正确生成，树内同 ID 漏洞是否已合并。`
- new: `6. 漏洞 ID 是否基于规范化相对路径的 file:func:line 正确生成，树内同 ID 漏洞是否已合并。`

- [ ] **Step 12: 验证本文件修改**

Run:
```bash
grep -n "绝对路径" taint-tree-checker/SKILL.md
grep -n "新格式\|旧格式" taint-tree-checker/SKILL.md
grep -c "规范化相对路径" taint-tree-checker/SKILL.md
```
Expected: 第 1 条仅输出 2 行（2.2 解析规则第 5 条、2.6 的 file 字段转换，均为转换规则）；第 2 条无输出；第 3 条输出 ≥4。

- [ ] **Step 13: 提交**

```bash
git add taint-tree-checker/SKILL.md
git commit -m "fix: use project_dir-relative paths in taint-tree-checker"
```

---

### Task 2: taint-path-checker/SKILL.md 路径规范改造

**Files:**
- Modify: `taint-path-checker/SKILL.md`

- [ ] **Step 1: 修改 2.2 JSON 示例中的 file 路径**

用 Edit 工具 `replace_all`：
- old: `"file": "/path/to/a.c"` → new: `"file": "src/a.c"`（共 2 处）
- old: `"file": "/path/to/b.c"` → new: `"file": "src/b.c"`（共 1 处）

- [ ] **Step 2: 修改 2.2 字段表格**

Edit：
- old: `| \`file\` | string | 函数所在源文件的绝对路径 |`
- new: `| \`file\` | string | 函数所在源文件路径，相对 \`<project_dir>\` |`

- [ ] **Step 3: 表格后新增解析规则**

Edit：
- old:
```
| `begin_line` | string | 函数定义起始行号 |

### 2.3 初始化输出目录
```
- new:
```
| `begin_line` | string | 函数定义起始行号 |

**解析规则（必须逐条执行）：**

1. **file 字段路径**：每个 chain 元素的 `file` 按 2.6 路径规范转换，转换失败（绝对路径不在 project_dir 内、规范化后含 `..` 段）在报告中报错并结束本次任务。

### 2.3 初始化输出目录
```

- [ ] **Step 4: 新增 2.6 路径规范小节**（插在 2.5 与"## 三"之间）

Edit：
- old:
```
检查 `{project_dir}/.ethunter_out/macro.json` 是否存在。若存在，读取并记住其中的宏定义（格式 `{"MACRO": "value", ...}`），这些是编译指令中动态定义的宏。若不存在则跳过，后续照常分析。

---

## 三、获取目标代码
```
- new:
```
检查 `{project_dir}/.ethunter_out/macro.json` 是否存在。若存在，读取并记住其中的宏定义（格式 `{"MACRO": "value", ...}`），这些是编译指令中动态定义的宏。若不存在则跳过，后续照常分析。

### 2.6 路径规范

- **规范化 norm(p)**：分隔符统一为 `/`；去掉前导 `./`（连续重复一并去掉）。规范化后含 `..` 段的路径非法（无法保证位于 project_dir 内），按解析规则报错并结束本次任务。
- **file 字段转换**：`file` 为相对路径时，norm 后直接使用；为绝对路径时，若以 `norm(project_dir)` 为前缀，去掉该前缀得相对路径；否则报错并结束本次任务。
- 转换得到的规范化相对路径（下称 rel）用于定位源码（`{project_dir}/{rel}`）、计算漏洞哈希（见 7.1）与报告展示（见 7.4）。

---

## 三、获取目标代码
```

- [ ] **Step 5: 修改"三、获取目标代码"第 1 步**

Edit：
- old: `1. 根据 \`file\` 和 \`begin_line\` 定位函数定义。`
- new: `1. 按 2.6 将 \`file\` 转换为 rel，以 \`{project_dir}/{rel}\` 定位函数定义并读取。`

- [ ] **Step 6: 修改 7.1 漏洞 ID 生成**（与 Task 1 Step 7 相同的替换）

Edit：
- old:
```
其中 `hash8` = 对字符串 `{文件绝对路径}:{函数名}:{起始行号}` 计算 SHA256，取前 8 位十六进制字符。
```
- new:
```
其中 `hash8` = 对字符串 `{rel}:{函数名}:{起始行号}` 计算 SHA256，取前 8 位十六进制字符。rel 为按 2.6 转换得到的规范化相对路径。
```

再 Edit：
- old:
```bash
echo -n "/srv/code/driver.c:npu_sem_alloc:380" | sha256sum | cut -c1-8
```
- new:
```bash
echo -n "src/driver.c:npu_sem_alloc:380" | sha256sum | cut -c1-8
```

注意：taint-path-checker 的 7.1 没有"起始行号为漏洞关键行号的起始行"那句（与 tree 版不同），所以分两个小 Edit，不要照抄 Task 1 的整块替换。

- [ ] **Step 7: 修改 7.4 模板"所在文件"**

Edit：
- old: `| **所在文件** | /绝对路径/file.c |`
- new: `| **所在文件** | src/file.c |`

- [ ] **Step 8: 修改 7.4 攻击路径示例**

Edit：
- old:
```
[1] /绝对路径/file_a.c:111  func_entry()
[2]   :49                    func_dispatch()
[3]   :230                   func_process()
[4] /绝对路径/file_b.c:78    func_trigger()  ← 触发点
```
- new:
```
[1] src/file_a.c:111  func_entry()
[2]   :49             func_dispatch()
[3]   :230            func_process()
[4] src/file_b.c:78   func_trigger()  ← 触发点
```

- [ ] **Step 9: 修改 7.4 攻击路径格式规则**

Edit：
- old: `- \`文件:行号  函数名()\`。同文件连续时后续步骤只写 \`:行号\`；跨文件时补全 \`/绝对路径/file.c:行号\`。`
- new: `- \`文件:行号  函数名()\`。同文件连续时后续步骤只写 \`:行号\`；跨文件时补全规范化相对路径 \`src/file.c:行号\`。`

- [ ] **Step 10: 修改检查清单第 4 条**

Edit：
- old: `4. 漏洞 ID 是否基于 file:func:line 正确生成。`
- new: `4. 漏洞 ID 是否基于规范化相对路径的 file:func:line 正确生成。`

- [ ] **Step 11: 验证本文件修改**

Run:
```bash
grep -n "绝对路径" taint-path-checker/SKILL.md
grep -n "新格式\|旧格式" taint-path-checker/SKILL.md
grep -c "规范化相对路径" taint-path-checker/SKILL.md
```
Expected: 第 1 条仅输出 2 行（2.2 解析规则、2.6 的 file 字段转换，均为转换规则）；第 2 条无输出；第 3 条输出 ≥4。

- [ ] **Step 12: 提交**

```bash
git add taint-path-checker/SKILL.md
git commit -m "fix: use project_dir-relative paths in taint-path-checker"
```

---

### Task 3: taint-path-cleaner/SKILL.md 相对路径解析

**Files:**
- Modify: `taint-path-cleaner/SKILL.md`

- [ ] **Step 1: 修改 4.1 第 1 步"定位源代码"**

Edit：
- old:
```
1. **定位源代码**：定位攻击路径中每一步的源代码文件。优先在 project_dir 中查找。
```
- new:
```
1. **定位源代码**：定位攻击路径中每一步的源代码文件。报告中的所在文件与攻击路径文件为相对 `<project_dir>` 的相对路径，按 `{project_dir}/{rel}` 拼接定位；若为绝对路径且以 project_dir 为前缀，去掉前缀后同样可定位。路径规范化（分隔符统一为 `/`、去掉前导 `./`）与 checker 一致。优先在 project_dir 中查找。
```

- [ ] **Step 2: 验证本文件修改**

Run:
```bash
grep -n "绝对路径\|相对路径" taint-path-cleaner/SKILL.md
```
Expected: 仅 4.1 第 1 步（新增文本）输出 1 行。

- [ ] **Step 3: 提交**

```bash
git add taint-path-cleaner/SKILL.md
git commit -m "fix: resolve report paths relative to project_dir in taint-path-cleaner"
```

---

### Task 4: 同步 .claude/skills 本地副本

**Files:**
- Modify（未跟踪、git 忽略）: `.claude/skills/taint-tree-checker/SKILL.md`、`.claude/skills/taint-path-checker/SKILL.md`、`.claude/skills/taint-path-cleaner/SKILL.md`

- [ ] **Step 1: 复制三个已修改的 SKILL.md 到 .claude/skills 副本**

Run:
```bash
cp taint-tree-checker/SKILL.md .claude/skills/taint-tree-checker/SKILL.md
cp taint-path-checker/SKILL.md .claude/skills/taint-path-checker/SKILL.md
cp taint-path-cleaner/SKILL.md .claude/skills/taint-path-cleaner/SKILL.md
```

- [ ] **Step 2: 验证副本与源文件一致**

Run:
```bash
diff taint-tree-checker/SKILL.md .claude/skills/taint-tree-checker/SKILL.md
diff taint-path-checker/SKILL.md .claude/skills/taint-path-checker/SKILL.md
diff taint-path-cleaner/SKILL.md .claude/skills/taint-path-cleaner/SKILL.md
```
Expected: 三条 diff 均无输出。

注：`.claude/skills/` 被 git 忽略，本任务无提交。

---

### Task 5: fixture 期望报告更新（6 份 result.md）

**Files:**
- Modify: `test_fixtures/{callback_fanout,fanout_limit,insufficient_check,multi_call_site,tree_repair,tree_test}/.ethunter_out/taint-tree-checker/*_result.md`

漏洞 ID 映射（已按新公式预计算，勿改动）：

| fixture | 源文件 rel | 旧 ID → 新 ID |
|---|---|---|
| callback_fanout | `test_fixtures/callback_fanout/test.c` | `fd593ace`→`8bbf8d43`，`0f4173ae`→`1094c181` |
| fanout_limit | `test_fixtures/fanout_limit/test.c` | `260a7509`→`3ecf115e`，`98ff1977`→`471514e7` |
| insufficient_check | `test_fixtures/insufficient_check/test.c` | `8ee72c47`→`750088e3`，`ba4f59e4`→`c633b1c9` |
| multi_call_site | `test_fixtures/multi_call_site/test.c` | `6279b391`→`a60f84b3` |
| tree_repair | `test_fixtures/tree_repair/test.c` | `4d15b5b2`→`4c66bf8c` |
| tree_test | `test_fixtures/tree_test/test.c` | `661d88c5`→`40d186a9`，`6d8cda29`→`ab07c1bd` |

- [ ] **Step 1: 写一次性变换脚本**

写文件 `/tmp/relpath_fixtures.py`：

```python
#!/usr/bin/env python3
import pathlib

P = "/home/admin/cc/wksp/siakam_security_skills/taint_path_checker"

FIXTURES = {
    "callback_fanout": ("test_fixtures/callback_fanout/test.c",
                        {"fd593ace": "8bbf8d43", "0f4173ae": "1094c181"}),
    "fanout_limit": ("test_fixtures/fanout_limit/test.c",
                     {"260a7509": "3ecf115e", "98ff1977": "471514e7"}),
    "insufficient_check": ("test_fixtures/insufficient_check/test.c",
                           {"8ee72c47": "750088e3", "ba4f59e4": "c633b1c9"}),
    "multi_call_site": ("test_fixtures/multi_call_site/test.c",
                        {"6279b391": "a60f84b3"}),
    "tree_repair": ("test_fixtures/tree_repair/test.c",
                    {"4d15b5b2": "4c66bf8c"}),
    "tree_test": ("test_fixtures/tree_test/test.c",
                  {"661d88c5": "40d186a9", "6d8cda29": "ab07c1bd"}),
}

REPORTS = {
    "callback_fanout": "fanout01_result.md",
    "fanout_limit": "fanout_limit01_result.md",
    "insufficient_check": "bypass01_result.md",
    "multi_call_site": "multi01_result.md",
    "tree_repair": "repair01_result.md",
    "tree_test": "ef4ebf80_result.md",
}

for name, fname in REPORTS.items():
    path = pathlib.Path(P) / "test_fixtures" / name / ".ethunter_out" / "taint-tree-checker" / fname
    rel, idmap = FIXTURES[name]
    txt = path.read_text(encoding="utf-8")
    before = txt
    txt = txt.replace(P + "/", "")                       # 绝对前缀剥离 → 相对路径
    txt = txt.replace("/* test.c:", "/* " + rel + ":")   # 代码片段注释相对化
    for old, new in idmap.items():                       # 漏洞 ID 替换
        txt = txt.replace("TAINT-" + old, "TAINT-" + new)
    assert P not in txt, f"{path}: 仍残留绝对路径"
    for old in idmap:
        assert f"TAINT-{old}" not in txt, f"{path}: 残留旧 ID {old}"
    path.write_text(txt, encoding="utf-8")
    print(f"updated {path.relative_to(P)}: {len(idmap)} ids, changed={txt != before}")
```

- [ ] **Step 2: 运行脚本**

Run: `python3 /tmp/relpath_fixtures.py`
Expected: 输出 6 行 `updated .../xxx_result.md: N ids, changed=True`（N 依次为 2、2、2、1、1、2）。

- [ ] **Step 3: 复核 diff**

Run: `git diff --stat test_fixtures/`
Expected: 6 个 result.md 被修改；tree_fixed.json、macro.json 无改动。

再抽查一份报告：
```bash
git diff test_fixtures/tree_test/.ethunter_out/taint-tree-checker/ef4ebf80_result.md | head -60
```
Expected: 可见 `/home/admin/...` 前缀被剥离、`TAINT-661d88c5`→`TAINT-40d186a9`、`TAINT-6d8cda29`→`TAINT-ab07c1bd`、`/* test_fixtures/tree_test/test.c:`。

- [ ] **Step 4: 哈希独立复核（不依赖脚本）**

Run:
```bash
echo -n "test_fixtures/tree_test/test.c:FUNC2:25" | sha256sum | cut -c1-8
echo -n "test_fixtures/tree_test/test.c:FUNC3:32" | sha256sum | cut -c1-8
echo -n "test_fixtures/callback_fanout/test.c:cb_b:15" | sha256sum | cut -c1-8
echo -n "test_fixtures/callback_fanout/test.c:helper_write:23" | sha256sum | cut -c1-8
```
Expected（依序）: `40d186a9`、`ab07c1bd`、`8bbf8d43`、`1094c181`。

- [ ] **Step 5: 提交**

```bash
git add test_fixtures
git commit -m "test: update expected reports to relative paths and rehashed vuln ids"
```

---

### Task 6: 未跟踪的 cleaner 本地产物同步

**Files:**
- Modify（未跟踪）: `test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-09f7dc3b.md`

该文件对应 tree_test 第一个漏洞（FUNC2:25），新 ID 为 `40d186a9`。

- [ ] **Step 1: 重命名文件**

Run:
```bash
mv test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-09f7dc3b.md \
   test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-40d186a9.md
```

- [ ] **Step 2: 内容变换（与 Task 5 同规则）**

Run:
```bash
sed -i 's|/home/admin/cc/wksp/siakam_security_skills/taint_path_checker/||g; s|/\* test\.c:|/* test_fixtures/tree_test/test.c:|g; s|TAINT-09f7dc3b|TAINT-40d186a9|g' \
  test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-40d186a9.md
```

- [ ] **Step 3: 验证**

Run:
```bash
grep -n "09f7dc3b\|661d88c5\|/home/admin" test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-40d186a9.md
grep -c "TAINT-40d186a9" test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-40d186a9.md
```
Expected: 第 1 条无输出；第 2 条输出 ≥1。

注：该文件未被 git 跟踪，无提交。

---

### Task 7: 全量验证与收尾

- [ ] **Step 1: 三个 SKILL.md 无历史性措辞、绝对路径仅限转换规则**

Run:
```bash
grep -rn "新格式\|旧格式" taint-tree-checker/SKILL.md taint-path-checker/SKILL.md taint-path-cleaner/SKILL.md
grep -n "绝对路径" taint-tree-checker/SKILL.md taint-path-checker/SKILL.md
grep -n "绝对路径" taint-path-cleaner/SKILL.md
```
Expected: 第 1 条无输出；第 2 条每个 checker 输出 2 行（2.2 解析规则、2.6 的 file 字段转换），共 4 行；第 3 条输出 1 行（cleaner 4.1 新增文本中的转换规则）。

- [ ] **Step 2: 两个 checker 的 2.6 小节逐字一致**

Run:
```bash
sed -n '/### 2.6 路径规范/,/^---$/p' taint-tree-checker/SKILL.md > /tmp/26t.md
sed -n '/### 2.6 路径规范/,/^---$/p' taint-path-checker/SKILL.md > /tmp/26p.md
diff /tmp/26t.md /tmp/26p.md
```
Expected: 无输出。

- [ ] **Step 3: 全部 fixture 报告无绝对路径、无旧 ID、ID 与哈希公式一致**

Run:
```bash
grep -rn "/home/admin" test_fixtures/*/.ethunter_out/taint-tree-checker/*_result.md
grep -rn "661d88c5\|6d8cda29\|fd593ace\|0f4173ae\|260a7509\|98ff1977\|8ee72c47\|ba4f59e4\|6279b391\|4d15b5b2" test_fixtures/
```
Expected: 两条均无输出。

再对全部报告做哈希一致性抽验：
```bash
python3 - <<'EOF'
import re, hashlib, glob
P="/home/admin/cc/wksp/siakam_security_skills/taint_path_checker"
for f in sorted(glob.glob(P+"/test_fixtures/*/.ethunter_out/taint-tree-checker/*_result.md")):
    txt=open(f,encoding='utf-8').read()
    for b in re.split(r'### 漏洞 TAINT-', txt)[1:]:
        vid=b[:8]
        mf=re.search(r'\|\s*\*\*所在文件\*\*\s*\|\s*(\S+)\s*\|',b)
        mfn=re.search(r'\|\s*\*\*所在函数\*\*\s*\|\s*(\S+)\s*\|',b)
        ml=re.search(r'\|\s*\*\*关键行号\*\*\s*\|\s*(\d+)(?:-\d+)?\s*\|',b)
        expect=hashlib.sha256(f"{mf.group(1)}:{mfn.group(1)}:{ml.group(1)}".encode()).hexdigest()[:8]
        assert vid==expect, f"{f}: TAINT-{vid} != TAINT-{expect}"
    print("OK", f.split("test_fixtures/")[1])
EOF
```
Expected: 输出 6 行 `OK ...`，无断言失败。

- [ ] **Step 4: tree_fixed.json 核对（应无需改动）**

Run:
```bash
grep -h '"file"' test_fixtures/callback_fanout/.ethunter_out/taint-tree-checker/fanout01_tree_fixed.json \
  test_fixtures/fanout_limit/.ethunter_out/taint-tree-checker/fanout_limit01_tree_fixed.json \
  test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_tree_fixed.json | sort -u
```
Expected: 全部为 `test_fixtures/...` 相对路径，无 `/home/...` 前缀。

- [ ] **Step 5: 工作区最终检查**

Run:
```bash
git status --short
git log --oneline -5
```
Expected: 除未跟踪的 rr1.txt、rr2.txt 外无其他未提交变更；最近提交包含本计划的 4 个提交（3 个 fix + 1 个 test）。
