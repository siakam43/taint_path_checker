# taint-tree-checker 污点数据流构建流程化设计

日期：2026-08-20
状态：已批准

## 背景与问题

实测报告中出现以下表述：

> `commu_amsm_recv_data`（commu_amsm.c:338）：接收污点 `payload` 和 `len`……污点传播至 `message_process` 中的用户注册回调（超过 20 个注册项，按扇出上限规则列出前 20 个注册点：blow_node.c:187、d2d_audio_channel.c:307……）。追踪至 `message_process` 后污点传入树外用户回调，目标不可逐一确定，标注"无法追踪"。

检查产出后发现三个问题：

1. **修复树缺链**：输出的 `{TreeID}_tree_fixed.json` 中，扇出解析出的注册点接口函数都不在调用树里——扇出分析结果没有落地到修复树。
2. **"无法追踪"误用**：前 20 个注册点已明确列出（含 file:line），目标**可确定**，却标注"目标不可逐一确定/无法追踪"——违反 4.3 现行规则（无法追踪仅限目标不可确定或源码缺失两类）。
3. **扇出被当作追踪终点**：扇出分析结束后没有继续追踪其余污点传播。

根因与第五章此前的问题同类：4.3 的"调用树修复规则""追踪上限""完整性自检"三块规则齐全，但**缺少流程主线说明**——AI 不知道修复过程中要应用追踪上限、修复结果（含扇出解析目标）要落盘、上限截断后要继续追踪。

## 目标

1. 4.3 引言改写为**污点传播数据流路线构建流程**主线，明确三步流程及其与 4.3.1/4.3.2/4.3.3 的关系。
2. 4.3 子节编号化：4.3.1 调用树修复规则、4.3.2 追踪上限、4.3.3 完整性自检，同步交叉引用。
3. 明确**扇出落盘**：扇出解析出的目标回调（上限内）必须补入修复树落盘；超限回调仅列摘要不补链。
4. 明确**截断≠终止**：上限截断只影响被截断分支，其余污点必须继续追踪。
5. 收紧 9.1/9.2 联动表述，禁止对可确定目标使用"无法追踪/不可逐一确定"标注。
6. 新增触发 20 扇出上限的测试夹具验证。

## 范围

- 只改 `taint-tree-checker/SKILL.md`。
- 新增夹具 `test_fixtures/fanout_limit/`。
- `.claude/skills/taint-tree-checker/SKILL.md` 为符号链接，无需单独修改。

## SKILL.md 修改点

### 1. 4.3 引言替换（流程主线）

现：

> 本阶段是全部分析的质量核心：数据流不完整则后续判定全部失真。以入口函数为起点，沿调用树追踪污点传播，**过程中修复调用树**，产出完整准确的污点数据流路线集合（包含污点数据在不同变量和函数间的传递过程），必须覆盖污点可达的全部代码。

改为：

> 本阶段的核心任务是构造完整准确的污点传播数据流路线，这是全部分析的质量核心，数据流不完整则后续判定全部失真。
>
> **污点传播数据流路线构建流程：**
>
> 1. 以 4.1 标记的初始污点为起点，以调用树信息为参考，按照 4.2 污点传播模式进行污点追踪，完整追踪污点数据的不同传播路线，记录每条污点传播路线中的具体函数调用点及参数、执行的条件分支、污点在变量间的传递过程等信息。最后对每一条污点传播路线执行"4.3.3 完整性自检"。最终产出完整且准确的污点传播数据流路线集合，覆盖污点可达的全部代码。
> 2. 在追踪污点传播数据流路线过程中，遇到调用深度过大或单个调用分发点目标过多时，按照"4.3.2 追踪上限"规则进行规模收敛。
> 3. 在追踪污点传播数据流路线过程中，如果调用树信息有误，按照"4.3.1 调用树修复规则"对调用树信息进行修正。

### 2. 子节编号化（3 个标题）

| 现标题 | 改为 |
|--------|------|
| `**调用树修复规则：**` | `**4.3.1 调用树修复规则：**` |
| `**追踪上限（目标可确定但规模巨大时）：**` | `**4.3.2 追踪上限（目标可确定但规模巨大时）：**` |
| `**完整性自检（本阶段结束前强制执行）**` | `**4.3.3 完整性自检（本阶段结束前强制执行）**` |

### 3. 交叉引用同步（2 处）

| 位置 | 原文 | 改为 |
|------|------|------|
| 4.3.2"上限内必须完整追踪到终态" | 追踪至 4.3 完整性自检的终态之一 | 追踪至 4.3.3 完整性自检的终态之一 |
| 4.4"树外函数追踪" | 按 4.3 调用链缺失/中断规则修复调用树 | 按 4.3.1 调用链缺失/中断规则修复调用树 |

### 4. "间接调用解析"补句 + 引用精确化

现：

> - **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数。**目标可确定时必须继续追踪，不得以"数量众多/链路深"为由放弃**；规模超出上限时按下方"追踪上限"规则处理。仅当目标不可确定（穷尽搜索注册点/赋值点仍无果、运行时计算地址、外部模块无源码）或源码缺失时，该分支标注"无法追踪"并停止延伸，不臆造——**标注时必须在摘要写明已尝试的搜索方式**。

改为：

> - **间接调用解析**：通过函数指针赋值、回调注册点在 project_dir 中搜索确定目标函数。**目标可确定时必须继续追踪，不得以"数量众多/链路深"为由放弃**；规模超出上限时按"4.3.2 追踪上限"规则处理。仅当目标不可确定（穷尽搜索注册点/赋值点仍无果、运行时计算地址、外部模块无源码）或源码缺失时，该分支标注"无法追踪"并停止延伸，不臆造——**标注时必须在摘要写明已尝试的搜索方式**。**解析出的目标函数（上限内）按"调用链缺失/中断"规则补入修复树并落盘。**

### 5. "落盘"条款明确扇出落盘

现：

> - **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。

改为：

> - **落盘**：有修复时，将修复后的调用树写入 `{project_dir}/.ethunter_out/taint-tree-checker/{TreeID}_tree_fixed.json`，格式与输入 JSON 一致；未修复则不生成该文件。不得修改输入文件。**扇出解析出的目标回调（上限内）与树外延伸链均属于修复内容，必须补入修复树落盘；超出上限的剩余回调不补入，仅在摘要逐条列出。**

### 6. 4.3.2 末尾新增"截断≠终止"

> - **截断≠终止**：因深度/扇出上限停止延伸的只是被截断的分支。该分支之外的污点变量、其他分支、其他链必须继续追踪，扇出/深度处理结束后分析照常进行，不得以上限为由提前结束整棵树的分析。

### 7. 9.1 思维陷阱行收紧

现：

> | "回调太多/链路太深，标无法追踪吧" | 数量与深度不是无法追踪的理由。上限内必须完整追踪；超出上限的逐条列出（函数名+行号），不得笼统跳过 |

改为：

> | "回调太多/链路太深，标无法追踪吧" | 数量与深度不是无法追踪的理由。对**可确定**目标使用"无法追踪/不可逐一确定"标注属于违规；上限内必须完整追踪，超出上限的逐条列出（函数名+行号），不得笼统跳过 |

### 8. 9.2 边缘情况行补充

现：

> | 间接调用扇出超出上限（深度>10 或单分发点回调>20） | 按"追踪上限"规则停止延伸，摘要逐条列出未深挖项（函数名+行号）；已追踪部分照常分析 |

改为：

> | 间接调用扇出超出上限（深度>10 或单分发点回调>20） | 按"4.3.2 追踪上限"规则停止延伸，摘要逐条列出未深挖项（函数名+行号）；超限回调不补入修复树，其余分支继续追踪，已追踪部分照常分析 |

## 新增测试夹具

```
test_fixtures/fanout_limit/
├── fanout_limit01.json                   # TreeID = fanout_limit01
├── test.c
└── .ethunter_out/taint-tree-checker/
    └── fanout_limit01_result.md          # 预期结果（git add -f 入库）
```

### test.c（22 回调触发扇出上限；行号与 JSON/漏洞 ID 强相关）

说明：cb_00..cb_17 为同构的"校验完备"回调，采用单行写法控制行号复杂度，行为与多行写法等价。

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

关键行号：cb_00=10 … cb_17=27、cb_18=28、cb_19=29、cb_20=30、cb_21=31、init_reg=33、func_after=43（危险行 45）、func_disp=48。

fanout_limit01.json 骨架（单链仅含 func_disp，逼 AI 走扇出解析）：

```json
{
    "func_disp$fanout_limit01": [
        [
            {"func": "func_disp", "file": "test_fixtures/fanout_limit/test.c", "begin_line": "48"}
        ]
    ]
}
```

### 预期报告与修复树

- **2 个漏洞**：
  - TAINT-260a7509：cb_19 内 `g_buf[idx] = 0x13`（行 29）无校验 → OOB Write
  - TAINT-98ff1977：func_after 内 `g_buf[idx] = 0xFF`（行 45）无校验 → OOB Write（验证扇出截断后继续追踪）
- 摘要逐回调给出一行结论：cb_00..cb_17 净化、cb_18 停止传播、cb_19 到达危险使用点、cb_20/cb_21 以"超限，未追踪"逐条列出；**全文不得出现"无法追踪/不可逐一确定"字样**（cb_20/cb_21 目标可确定，仅因上限不追踪）。
- **修复树 21 条链**：func_disp → cb_00 … func_disp → cb_19（20 条）+ func_disp → func_after（1 条）；cb_20/cb_21 不在树中。

## 验证方式

1. 基线（RED）：用当前技能跑 `fanout_limit01.json`，预期复现用户实测问题（标注"无法追踪"、修复树缺链、func_after 分支可能漏报），记录基线证据。
2. 修改 SKILL.md 后重跑（GREEN）：核对 2 个漏洞 ID、摘要 20+2 逐回调结论、修复树 21 条链、无"无法追踪/不可逐一确定"字样。
3. 回归：callback_fanout（4 回调扇出，验证小规模扇出行为不变：2 漏洞、修复树 4 条链）、tree_test、tree_repair 重跑比对。

## 非目标

- 不修改 taint-path-checker、taint-path-cleaner。
- 不修改上限数值（深度 10、扇出 20 保持常量）。
- 不修改"仅污点驱动"防路径爆炸规则（回调未接收污点时不补链保持不变；本夹具所有回调均接收 idx，不受影响）。
- 不修改漏洞上报格式与门禁三问。
- 不引入两遍法（先浅扫后深挖）。
