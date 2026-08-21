# 设计：taint 系列 skill 路径相对化（relative to project_dir）

日期：2026-08-21
范围：taint-tree-checker、taint-path-checker、taint-path-cleaner 三个 SKILL.md 及其 fixture 期望报告

## 1. 背景与动机

上游调用树/调用链生成工具产出的 JSON 中，`file` 字段已改为相对 `<project_dir>` 的相对路径（本仓库全部 fixture 输入已是相对路径，如 `test_fixtures/tree_test/test.c`）。但三个 skill 的正文与既有产出仍以绝对路径为准：

- 两个 checker 的 SKILL.md 中 `file` 字段说明、漏洞哈希公式、报告模板（所在文件、攻击路径）均要求绝对路径；
- git 跟踪的 6 份期望报告含绝对路径，其漏洞 ID 基于绝对路径哈希（已实测验证：`TAINT-661d88c5` = sha256 绝对路径串前 8 位，相对路径串应为 `40d186a9`）；
- 绝对路径哈希随代码检出位置变化，跨机器、跨检出目录无法去重。

目标：输入解析、报告展示、漏洞哈希统一使用相对 `<project_dir>` 的规范化相对路径；绝对路径输入按规则转换。

约束（用户要求）：skill 正文只描述现行规范行为，不出现"新格式/旧格式"之类的措辞，不体现变动历史。

## 2. 路径规范核心规则（两个 checker 共用措辞，逐字一致）

### 2.1 规范化 norm(p)

对路径字符串执行，哈希与报告显示前统一执行：

1. 分隔符统一为 `/`（`\` → `/`）；
2. 去掉前导 `./`（连续重复一并去掉）；
3. 规范化后若含 `..` 段 → 无法保证文件位于 project_dir 内，按解析规则报错并结束本次任务。

### 2.2 输入 file 字段转换（解析规则）

- `file` 为相对路径：norm 后直接使用；
- `file` 为绝对路径：若以 `norm(project_dir)` 为前缀，去掉该前缀得相对路径；否则报错并结束本次任务（文件不在 project_dir 内）。

转换得到的规范化相对路径 rel 用于后续全部环节：读取源码、计算哈希、报告展示、tree_fixed.json 落盘。

### 2.3 内部读取源码

Read 工具使用 `{project_dir}/{rel}` 拼接后的绝对路径定位文件。

### 2.4 漏洞哈希

`hash8` = 对字符串 `{rel}:{函数名}:{起始行号}` 计算 SHA256，取前 8 位十六进制字符。起始行号语义不变（漏洞关键行号的起始行）。bash 示例：

```bash
echo -n "src/driver.c:npu_sem_alloc:380" | sha256sum | cut -c1-8
```

### 2.5 报告展示

- 所在文件：规范化相对路径（无前导 `/`），如 `src/driver.c`；
- 攻击路径：`[1] src/file_a.c:111  func_entry()`，跨文件时补全相对路径，同文件连续步骤缩写 `:行号` 规则不变；
- 关键代码片段注释中的文件引用同样使用规范化相对路径；
- 在 project_dir 内搜索到的树外函数位置，同样以相对路径呈现。

### 2.6 操作路径不变

输出目录、结果文件路径、跳过提示、macro.json 路径等操作位置仍使用 `{project_dir}/.ethunter_out/...` 形式，不属于报告内容路径，不做相对化。

## 3. taint-tree-checker 修改点

| 位置 | 修改 |
|------|------|
| 2.2 表格 `file` 说明 | 改为"函数所在源文件路径，相对 `<project_dir>`" |
| 2.2 JSON 示例 | `/src/a.c` → `src/a.c` |
| 2.2 解析规则 | 新增一条：file 字段按 2.6 转换，转换失败报错并结束任务 |
| 新增 2.6 路径规范 | 第 2 节的 2.1~2.3 完整规则（含 tree_fixed.json 的 file 使用 rel） |
| 三. 获取目标代码 | 第 1 步：按 2.6 转换得 rel，用 `{project_dir}/{rel}` 定位读取 |
| 4.3.1 落盘 | 明确 tree_fixed.json 的 file 字段使用规范化相对路径 |
| 7.1 哈希 | 改为 `{rel}:{函数名}:{起始行号}`，bash 示例更新为相对路径 |
| 7.4 模板 | 所在文件、攻击路径模板与格式规则改为相对路径写法 |
| 八. 检查清单第 6 条 | 措辞明确"基于规范化相对路径的 file:func:line" |

## 4. taint-path-checker 修改点

与第 3 节同构：

| 位置 | 修改 |
|------|------|
| 2.2 表格 `file` 说明 | 改为"函数所在源文件路径，相对 `<project_dir>`" |
| 2.2 JSON 示例 | `/path/to/a.c` → `src/a.c`，`/path/to/b.c` → `src/b.c` |
| 2.2 后 | 新增解析规则一条：file 字段按 2.6 转换，转换失败报错并结束任务 |
| 新增 2.6 路径规范 | 第 2 节的 2.1~2.3 规则（无 tree_fixed.json 相关内容） |
| 三. 获取目标代码 | 第 1 步：按 2.6 转换得 rel，用 `{project_dir}/{rel}` 定位读取 |
| 7.1 哈希 | 改为 `{rel}:{函数名}:{起始行号}`，bash 示例同步更新 |
| 7.4 模板 | 所在文件、攻击路径模板与格式规则改为相对路径写法 |
| 八. 检查清单第 4 条 | 措辞明确"基于规范化相对路径的 file:func:line" |

## 5. taint-path-cleaner 修改点

cleaner 不计算哈希、不产出路径内容，仅在定位源码处适配相对路径：

| 位置 | 修改 |
|------|------|
| 4.1 第 1 步"定位源代码" | 补充路径解析规则：报告中的所在文件/攻击路径文件为相对 `<project_dir>` 的相对路径，按 `{project_dir}/{rel}` 拼接定位；若为绝对路径且以 project_dir 为前缀，同样可定位。规范化规则与两个 checker 相同 |
| 其余 | 3.3、7.2 边缘情况条目不变，天然覆盖；输出文件名沿用报告中的漏洞 ID，不变 |

## 6. fixture 期望报告更新

### 6.1 git 跟踪文件（10 个）

- **6 份 result.md**（tree_test/ef4ebf80、callback_fanout/fanout01、fanout_limit/fanout_limit01、tree_repair/repair01、insufficient_check/bypass01、multi_call_site/multi01）：
  - 所在文件、攻击路径、关键代码片段注释改为规范化相对路径；
  - 每个漏洞 ID 按新公式重算并全文替换（标题、表格、正文引用处）。已预验证 tree_test：`FUNC2:25` → `TAINT-40d186a9`，`FUNC3:32` → `TAINT-ab07c1bd`；其余 fixture 实现时逐一重算。
- **3 份 tree_fixed.json**（callback_fanout、fanout_limit、tree_repair）：file 字段已是相对路径，核对与规范化结果一致即可，不改动。
- **macro.json**：无路径，不动。

### 6.2 未跟踪本地产物

- `test_fixtures/tree_test/.ethunter_out/taint-path-cleaner/Vulns/TAINT-09f7dc3b.md` 未纳入 git，实现时同步更新为新 ID（`TAINT-40d186a9`）以保持本地一致。

### 6.3 `.claude/skills/` 副本

`.claude/skills/{taint-tree-checker,taint-path-checker,taint-path-cleaner}/SKILL.md` 为未跟踪的本地同步副本（当前与源文件逐字一致），实现时同步更新三份，保持本地 skill 行为与仓库一致。

## 7. 验证方式

1. **哈希重算**：用 bash 对每个 fixture 的每个漏洞执行 `echo -n "{rel}:{func}:{line}" | sha256sum | cut -c1-8`，与更新后报告中的 ID 逐一比对；
2. **规则文本核对**：grep 三个 SKILL.md，确认不再出现"绝对路径"作为规范性要求；两个 checker 的路径规范小节逐字一致；不出现"新格式/旧格式"等历史性措辞；
3. **端到端回归（可选）**：删除某 fixture 的 result.md 后重跑 skill，核对产出符合新格式。

## 8. 不做的事

- 不修改 `{project_dir}/.ethunter_out/...` 输出目录结构；
- 不修改输入 JSON 的顶层键格式、TreeID/callchainID 规则、预查重逻辑；
- 不新增共享文档或脚本，规则全部内联在各 SKILL.md；
- 不修改 taint 系列之外的 skill。
