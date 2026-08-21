# 污点树分析报告

- **调用树ID**：ef4ebf80
- **分析时间**：2026-08-18 16:28:42
- **结论**：发现 2 个安全漏洞

## 分析情况

调用树共含 2 条链（入口函数 FUNC0，参数 `cmd`、`idx` 均为外部输入），均已纳入数据流追踪：

- **链1（FUNC0 → FUNC1 → FUNC2）**：入口参数 `cmd==0` 时进入。污点 `idx` 经 FUNC1 原样传递，并在 FUNC1 中写入全局变量 `g_flag`（污点写入全局，全树共享）；到达 FUNC2 后 `idx` 直接作为全局数组 `g_buf[64]` 的下标写入，**无任何校验**，存在越界写漏洞。
- **链2（FUNC0 → FUNC3）**：入口参数 `cmd!=0` 时进入。FUNC3 对 `idx` 进行了 `idx >= BUF_SIZE` 上界校验，`idx` 被净化；但函数内 `g_buf[g_flag]` 使用的 `g_flag` 是链1上一次调用写入的污点（全局污点全树共享），**未做任何校验**，存在跨调用越界写漏洞。

**调用树修复情况**：未修复。污点传播路径（FUNC0 → FUNC1 → FUNC2、FUNC0 → FUNC3）全部落在输入调用树内，无树外分支、无提前中断，输入树已完整，无需补充或延伸链，不生成 `ef4ebf80_tree_fixed.json`。

**污点状态追踪**：`idx`（链1）→ 到达 FUNC2 危险使用点；`idx`（链2）→ FUNC3 校验后净化；`g_flag`（链1 写入）→ 链2 FUNC3 到达危险使用点；`cmd` → 仅用于 if 分发，被分支消费。全部污点变量均达终态。

**跨调用触发前提核查**：入口函数 FUNC0 及各条链的必经路径均不重置/初始化 `g_flag`（静态全局变量，仅初始化为 0，FUNC1 每次写入均来自外部输入），跨调用传播成立。

## 漏洞列表

### 漏洞 TAINT-40d186a9

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-40d186a9 |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | test_fixtures/tree_test/test.c |
| **所在函数** | FUNC2 |
| **关键行号** | 25 |
| **是否链外** | 否 |

#### 漏洞描述

外部输入 `idx` 未经任何校验直接作为全局数组 `g_buf[64]` 的下标进行写入，攻击者可通过构造入口参数 `cmd=0`、`idx` 为任意大值，实现全局缓冲区越界写，破坏相邻全局变量（如 `g_flag`）或其他内存数据。

#### 漏洞原理

1. 入口函数 `FUNC0(cmd, idx)` 的两个参数均为外部输入，其中 `idx` 为污点数据。
2. 当 `cmd == 0`（`cmd` 经 if 分支判断后进入该分支）时，`FUNC0` 将污点 `idx` 原样传入 `FUNC1(idx)`。
3. `FUNC1` 将污点 `idx` 原样传入 `FUNC2(idx)`（同时把污点写入全局变量 `g_flag`，全树共享，见下一漏洞）。
4. `FUNC2` 中执行 `g_buf[idx] = 0xAA`：污点 `idx`（`uint32_t`）直接作为下标索引全局数组 `g_buf`（大小 `BUF_SIZE = 64`），此前无 `idx < BUF_SIZE` 之类的任何上界校验。
5. 越界写可覆盖 `g_buf` 之后的全局数据（如 `g_flag`），造成内存破坏。

**校验点检查**：从入口到漏洞点（FUNC0 → FUNC1 → FUNC2），对 `idx` 无显式边界检查、无隐式校验（无掩码、无类型窄化、无 switch/if-else 值过滤）；`cmd` 的 `if (cmd == 0)` 仅约束分支选择，不约束 `idx` 的取值。故该漏洞满足"未校验"门禁。

**门禁三问**：可触发——单次调用 `FUNC0(cmd=0, idx=任意大值)` 即可触发，路径 FUNC0 → FUNC1 → FUNC2；未校验——`idx` 到达 `g_buf[idx]` 前无任何显式/隐式校验；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/tree_test/test.c:8   FUNC0(cmd=0, idx=0x80000000)()
[2]   :17                    FUNC1()
[3]   :23                    FUNC2()  ← 触发点（g_buf[idx] = 0xAA，idx 无校验）
```

#### 关键代码片段

```c
/* test_fixtures/tree_test/test.c:8  入口函数，cmd、idx 均为外部输入 */
void FUNC0(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {          /* cmd 隐式校验为 0，但 idx 不受约束 */
        FUNC1(idx);          /* 污点 idx 原样传递 */
    } else {
        FUNC3(idx);
    }
}

/* test_fixtures/tree_test/test.c:17 */
void FUNC1(uint32_t idx)
{
    g_flag = idx;            /* 污点写入全局 g_flag（全树共享） */
    FUNC2(idx);              /* 污点 idx 继续传递 */
}

/* test_fixtures/tree_test/test.c:23 */
void FUNC2(uint32_t idx)
{
    g_buf[idx] = 0xAA;       /* ← 危险点：污点 idx 作数组下标，无上界校验，
                              *   g_buf 仅 64 字节，idx 为任意 uint32_t 值 */
}
```

#### 修复建议

在污点下标使用前增加上界校验，例如在 `FUNC2` 入口处校验：

```c
void FUNC2(uint32_t idx)
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xAA;
}
```

或参照链2中 `FUNC3` 的既有做法，在 `FUNC0`/`FUNC1` 入口处统一对 `idx` 校验后再分发，保证所有使用路径均被覆盖。

### 漏洞 TAINT-ab07c1bd

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-ab07c1bd |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | test_fixtures/tree_test/test.c |
| **所在函数** | FUNC3 |
| **关键行号** | 32 |
| **是否链外** | 否 |

#### 漏洞描述

链2 函数 FUNC3 中，全局变量 `g_flag` 在链1上一次调用（FUNC1 中 `g_flag = idx`）中被污染为任意外部值，本次调用中未经验证直接作为全局数组 `g_buf[64]` 的下标写入，攻击者通过两次调用即可实现全局缓冲区越界写。

#### 漏洞原理

1. 入口函数 `FUNC0(cmd, idx)` 的两个参数均为外部输入，均为污点数据。
2. **第一次调用沿链1设置 g_flag**：`FUNC0(cmd=0, idx=任意大值)` 进入 FUNC1，FUNC1 执行 `g_flag = idx`，将污点值写入全局变量 `g_flag`。按全树共享规则，污点写入全局/静态变量后，调用树内任何后续函数（包括其他链中的函数）读取时均视为污点。
3. **第二次调用沿链2触发**：`FUNC0(cmd=1, idx=小值)` 进入 FUNC3。FUNC3 先对 `idx` 执行 `if (idx >= BUF_SIZE) return;` 上界校验——该校验仅覆盖 `idx`，不覆盖 `g_flag`。
4. FUNC3 中执行 `g_buf[g_flag] = 0xCC`：`g_flag` 为第一次调用写入的污点值（如 `0x80000000`），直接作为下标索引全局数组 `g_buf`（大小 `BUF_SIZE = 64`），此前无 `g_flag < BUF_SIZE` 之类的任何校验。
5. 越界写可覆盖 `g_buf` 之后的全局数据，造成内存破坏。

**跨调用触发前提核查**：入口函数 FUNC0 及各链必经路径均不重置 `g_flag`（无清零、无重新赋值），故第一次调用写入的污点 g_flag 可在第二次调用中保持并触发。跨调用传播成立。

**校验点检查**：`g_flag` 从被污染（链1 FUNC1）到危险使用点（链2 FUNC3）之间无任何显式/隐式校验；FUNC3 中对 `idx` 的校验仅覆盖 `idx` 本身，不覆盖 `g_flag`。故该漏洞满足"未校验"门禁。

**门禁三问**：可触发——需要两次调用：第一次调用 `FUNC0(cmd=0, idx=任意大值)` 沿链1设置 `g_flag`，第二次调用 `FUNC0(cmd=1, idx=0)` 沿链2在 FUNC3 触发 `g_buf[g_flag]` 越界写；未校验——`g_flag` 到达数组下标前无任何校验；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径（跨调用触发，需两次调用；第一次沿链1设置 g_flag，第二次沿链2触发）：

[1] 第一次调用：test_fixtures/tree_test/test.c:8   FUNC0(cmd=0, idx=0x80000000)()
[2]   :17                    FUNC1()
[3]   :19                    g_flag = idx        （污点写入全局 g_flag）
[4] 第二次调用：test_fixtures/tree_test/test.c:8   FUNC0(cmd=1, idx=0)()
[5]   :28                    FUNC3()             （idx 通过 idx < 64 校验，不覆盖 g_flag）
[6]   :32                    g_buf[g_flag] = 0xCC  ← 触发点（g_flag 为首次调用写入的污点大值，无校验）
```

#### 关键代码片段

```c
/* test_fixtures/tree_test/test.c:17  第一次调用沿链1：污点写入全局 g_flag（全树共享） */
void FUNC1(uint32_t idx)
{
    g_flag = idx;            /* ← 链1写入全局变量 g_flag = 污点 idx */
    FUNC2(idx);
}

/* test_fixtures/tree_test/test.c:28  第二次调用沿链2：触发点 */
void FUNC3(uint32_t idx)
{
    if (idx >= BUF_SIZE)     /* 仅校验 idx，不覆盖 g_flag */
        return;
    g_buf[g_flag] = 0xCC;    /* ← 危险点：g_flag 为前次调用污染的全局值，
                              *   作数组下标无上界校验，g_buf 仅 64 字节 */
}
```

#### 修复建议

在 `g_flag` 用作数组下标前增加上界校验，例如：

```c
void FUNC3(uint32_t idx)
{
    if (idx >= BUF_SIZE)
        return;
    if (g_flag >= BUF_SIZE)  /* 对全局污点下标单独校验 */
        return;
    g_buf[g_flag] = 0xCC;
}
```

或从根源上消除跨调用污染：在入口函数 `FUNC0` 入口处重置 `g_flag = 0`（每次调用清零，阻断跨调用传播），并在 `FUNC1` 写入 `g_flag` 前对 `idx` 校验，保证写入 `g_flag` 的值始终在界内。
