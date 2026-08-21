# 污点树分析报告

- **调用树ID**：fanout01
- **分析时间**：2026-08-19 10:00:41
- **结论**：发现 2 个安全漏洞

## 分析情况

调用树共含 1 条链（入口函数 func_disp，参数 `ver`、`idx` 均为外部输入），已纳入数据流追踪：

- **链1（func_disp）**：入口函数通过函数指针表 `g_cbs[ver]` 间接调用回调函数（`ver < CB_COUNT` 时）。经搜索注册点 `init_reg`（test.c:30）确定 g_cbs 表项指向 4 个回调：cb_a、cb_b、cb_c、cb_d。扇出规模（4 个回调）在上限内，**逐一完整追踪**，逐回调结论如下：

| 回调 | 结论 |
|------|------|
| cb_a | 接收污点 idx；`idx >= BUF_SIZE` 上界校验（uint32 完备）后净化，无漏洞 |
| cb_b | 接收污点 idx；无校验直接作数组下标，到达危险使用点（漏洞 TAINT-8bbf8d43） |
| cb_c | 接收污点 idx；传递至树外函数 helper_write，补链后到达危险使用点（漏洞 TAINT-1094c181） |
| cb_d | 接收污点 idx 但未使用（仅写 `g_buf[0]` 常量），污点停止传播 |

**调用树修复情况**：输入树在 func_disp 的间接调用处中断，按 4.3 间接调用解析+补链规则修复——从入口函数补写 4 条新链（func_disp → cb_a；func_disp → cb_b；func_disp → cb_c → helper_write；func_disp → cb_d），均已写入 `fanout01_tree_fixed.json`，输入文件 `fanout01.json` 未被修改。四条补链依据"仅污点驱动"：实参 idx 含污点，均计入树。

**污点状态追踪**：`ver` → `ver < CB_COUNT` 约束后用于索引函数表，被分支选择消费；`idx` → cb_a 净化 / cb_b 危险使用 / cb_c→helper_write 危险使用 / cb_d 停止传播。全部污点变量均达终态（净化/危险使用点/停止传播），无"无法追踪"分支。

## 漏洞列表

### 漏洞 TAINT-8bbf8d43

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-8bbf8d43 |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | test_fixtures/callback_fanout/test.c |
| **所在函数** | cb_b |
| **关键行号** | 15 |
| **是否链外** | 否 |

#### 漏洞描述

入口参数 `idx` 经函数指针表 `g_cbs[ver]` 分发至回调 cb_b，cb_b 中 `idx` 未经任何校验直接作为全局数组 `g_buf[64]` 的下标写入，攻击者以 `ver=1`、`idx` 为任意大值调用即可越界写。

#### 漏洞原理

1. 入口函数 `func_disp(ver, idx)` 的两个参数均为外部输入，`idx` 为污点数据。
2. `ver < CB_COUNT` 时，`g_cbs[ver](idx)` 间接调用注册回调；注册点 `init_reg`（test.c:30）确定 `g_cbs[1] = cb_b`。
3. 污点 `idx` 原样传入 `cb_b(idx)`（间接调用目标已解析，补链 func_disp → cb_b）。
4. cb_b 中执行 `g_buf[idx] = 0xBB`：污点 `idx`（`uint32_t`）直接作为下标索引全局数组 `g_buf`（`BUF_SIZE = 64`），此前从入口到该点无任何上界校验。
5. 越界写可覆盖 `g_buf` 之后的全局数据，造成内存破坏。

**校验点检查**：func_disp → cb_b 路径上对 `idx` 无显式边界检查、无隐式校验（无掩码、无类型窄化、无值过滤）；`ver < CB_COUNT` 仅约束函数表索引，不约束 `idx` 取值。满足"未正确校验"门禁（不存在校验）。

**门禁三问**：可触发——单次调用 `func_disp(ver=1, idx=任意大值)` 即触发；未正确校验——`idx` 到达 `g_buf[idx]` 前无任何校验；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/callback_fanout/test.c:35   func_disp(ver=1, idx=0x80000000)()
[2]   :38                    g_cbs[1](idx) → cb_b（函数表间接调用，注册点 init_reg 解析）
[3]   :15                    cb_b()  ← 触发点（g_buf[idx] = 0xBB，idx 无校验）
```

#### 关键代码片段

```c
/* test_fixtures/callback_fanout/test.c:35  入口函数，ver、idx 均为外部输入 */
void func_disp(uint32_t ver, uint32_t idx)
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);            /* ← 间接调用扇出：目标经 init_reg 注册点确定 */
}

/* test_fixtures/callback_fanout/test.c:30  注册点（间接调用解析依据） */
void init_reg(void)
{
    g_cbs[0] = cb_a; g_cbs[1] = cb_b;
    g_cbs[2] = cb_c; g_cbs[3] = cb_d;
}

/* test_fixtures/callback_fanout/test.c:14  回调2：危险使用点 */
static void cb_b(uint32_t idx)
{
    g_buf[idx] = 0xBB;              /* ← 污点 idx 作数组下标，无上界校验，
                                     *   g_buf 仅 64 字节 */
}
```

#### 修复建议

在 cb_b 入口处对 `idx` 增加上界校验（参照 cb_a 的既有做法）：

```c
static void cb_b(uint32_t idx)
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xBB;
}
```

或统一在 func_disp 分发前校验 `idx`，保证所有回调路径均被覆盖。

### 漏洞 TAINT-1094c181

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-1094c181 |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | test_fixtures/callback_fanout/test.c |
| **所在函数** | helper_write |
| **关键行号** | 23 |
| **是否链外** | 否 |

#### 漏洞描述

入口参数 `idx` 经 `g_cbs[ver]` 分发至回调 cb_c，cb_c 将污点 `idx` 原样传入树外函数 helper_write，helper_write 中 `idx` 未经任何校验直接作为全局数组 `g_buf[64]` 的下标写入，攻击者以 `ver=2`、`idx` 为任意大值调用即可越界写。

#### 漏洞原理

1. 入口函数 `func_disp(ver, idx)` 的 `idx` 为污点数据。
2. `ver < CB_COUNT` 时 `g_cbs[ver](idx)` 间接调用；注册点 `init_reg` 确定 `g_cbs[2] = cb_c`。
3. 污点 `idx` 传入 `cb_c(idx)`（补链 func_disp → cb_c），cb_c 内执行 `helper_write(idx)`——污点传递到树外函数。
4. 按 4.4 树外函数追踪规则在 project_dir 中查找 helper_write 定义（test.c:22），污点在该函数内继续传播，按 4.3 补链延伸为 func_disp → cb_c → helper_write。
5. helper_write 中执行 `g_buf[idx] = 0xCC`：污点 `idx` 直接作为下标索引 `g_buf`（`BUF_SIZE = 64`），从入口到该点无任何上界校验。
6. 越界写可覆盖 `g_buf` 之后的全局数据，造成内存破坏。

**校验点检查**：func_disp → cb_c → helper_write 路径上对 `idx` 无显式边界检查、无隐式校验；`ver < CB_COUNT` 仅约束函数表索引。满足"未正确校验"门禁（不存在校验）。

**门禁三问**：可触发——单次调用 `func_disp(ver=2, idx=任意大值)` 即触发，路径 func_disp → cb_c → helper_write；未正确校验——`idx` 到达 `g_buf[idx]` 前无任何校验；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/callback_fanout/test.c:35   func_disp(ver=2, idx=0x80000000)()
[2]   :38                    g_cbs[2](idx) → cb_c（函数表间接调用）
[3]   :19                    helper_write(idx)（污点传递至树外，补链延伸）
[4]   :23                    helper_write()  ← 触发点（g_buf[idx] = 0xCC，idx 无校验）
```

#### 关键代码片段

```c
/* test_fixtures/callback_fanout/test.c:18  回调3：污点继续传递至树外 */
static void cb_c(uint32_t idx)
{
    helper_write(idx);              /* 污点 idx 传入树外函数 */
}

/* test_fixtures/callback_fanout/test.c:22  树外辅助函数：危险使用点 */
static void helper_write(uint32_t idx)
{
    g_buf[idx] = 0xCC;              /* ← 污点 idx 作数组下标，无上界校验，
                                     *   g_buf 仅 64 字节 */
}
```

#### 修复建议

在 helper_write 入口处对 `idx` 增加上界校验，或在 cb_c 调用前校验：

```c
static void helper_write(uint32_t idx)
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xCC;
}
```

或统一在 func_disp 分发前校验 `idx`，保证所有回调路径均被覆盖。
