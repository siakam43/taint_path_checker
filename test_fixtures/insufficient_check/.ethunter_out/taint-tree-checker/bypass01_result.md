# 污点树分析报告

- **调用树ID**：bypass01
- **分析时间**：2026-08-19 09:23:20
- **结论**：发现 2 个安全漏洞

## 分析情况

调用树共含 3 条链（入口函数 FUNC0，参数 `idx`、`off`、`len` 均为外部输入），均已纳入数据流追踪：

- **链1（FUNC0 → FUNC1）**：入口参数 `len==0` 时进入。污点 `idx`、`off` 传入 FUNC1，FUNC1 使用前有 `if (idx + off >= BUF_SIZE) return;` 校验，但该校验表达式本身可整数回绕被绕过（见漏洞 TAINT-8ee72c47），校验不完备。
- **链2（FUNC0 → FUNC2）**：入口参数 `len==1` 时进入。污点 `idx` 传入 FUNC2（uint32 实参隐式转换为 int32 形参，符号性翻转），FUNC2 使用前有 `if (idx >= BUF_SIZE) return;` 上界校验，但负数可绕过（见漏洞 TAINT-ba4f59e4），校验不完备。
- **链3（FUNC0 → FUNC3）**：入口参数 `len` 为其他值时进入。污点 `len`（uint32）传入 FUNC3，`if (len >= BUF_SIZE) return;` 对无符号值即完备上界校验，`len` 被正确净化，**未发现漏洞**。

**调用树修复情况**：未修复。污点传播路径全部落在输入调用树内，无需补充或延伸链，不生成 `bypass01_tree_fixed.json`。

**污点状态追踪**：`idx`（链1）→ FUNC1 危险使用点（校验可绕过）；`idx`（链2）→ FUNC2 危险使用点（校验可绕过）；`off`（链1）→ 参与校验表达式后被消费；`len` → 用于分支分发与链3，FUNC3 校验后净化。全部污点变量均达终态。

## 漏洞列表

### 漏洞 TAINT-8ee72c47

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-8ee72c47 |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c |
| **所在函数** | FUNC1 |
| **关键行号** | 18 |
| **是否链外** | 否 |

#### 漏洞描述

外部输入 `idx` 用作全局数组 `g_buf[64]` 的下标前虽有 `if (idx + off >= BUF_SIZE) return;` 校验，但校验表达式 `idx + off` 本身为 uint32 加法，可整数回绕为小值通过校验，随后 `g_buf[idx]` 以巨大的 `idx` 越界写。

#### 漏洞原理

1. 入口函数 `FUNC0(idx, off, len)` 的三个参数均为外部输入，`idx`、`off` 为污点数据。
2. 当 `len == 0` 时，污点 `idx`、`off` 原样传入 `FUNC1(idx, off)`。
3. FUNC1 中执行 `if (idx + off >= BUF_SIZE) return;`：该检查**存在**，但校验表达式 `idx + off` 是 uint32 加法，**本身可溢出回绕**（5.3②"校验表达式本身溢出"）。
4. 具体绕过输入：`idx = 0xFFFFFFFF`、`off = 2` 时，`idx + off` 回绕为 `1`，`1 >= 64` 为假，校验通过；随后 `g_buf[idx]` 实际以 `0xFFFFFFFF` 为下标写入，超出 `g_buf`（64 字节）约 40 亿字节，任意地址越界写。
5. 越界写可覆盖 `g_buf` 之后的全局/静态数据或不可预测的内存区域，造成内存破坏。

**校验点检查**：`idx + off >= BUF_SIZE` 属 5.2 显式 if 边界检查，覆盖"有校验"；但按 5.3 完备性检查，该校验表达式本身参与无符号加法、可回绕，绕过输入（idx=0xFFFFFFFF, off=2）已具体给出，判定校验无效。

**门禁三问**：可触发——单次调用 `FUNC0(len=0, idx=0xFFFFFFFF, off=2)` 即触发，路径 FUNC0 → FUNC1；未正确校验——校验存在但可被整数回绕绕过（具体输入已论证）；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c:7   FUNC0(len=0, idx=0xFFFFFFFF, off=2)()
[2]   :14                    FUNC1()
[3]   :16                    idx + off 回绕为 1，通过 >= 64 校验
[4]   :18                    g_buf[idx] = 0xAA  ← 触发点（idx=0xFFFFFFFF 越界写）
```

#### 关键代码片段

```c
/* test.c:14 */
void FUNC1(uint32_t idx, uint32_t off)
{
    if (idx + off >= BUF_SIZE)   /* ← 校验表达式本身可回绕：
                                  *   idx=0xFFFFFFFF, off=2 → idx+off=1，
                                  *   1 >= 64 为假，校验被绕过 */
        return;
    g_buf[idx] = 0xAA;           /* ← 危险点：idx=0xFFFFFFFF 作下标，
                                  *   g_buf 仅 64 字节，任意地址越界写 */
}
```

#### 修复建议

校验前先单独约束 `idx` 与 `off` 的上界，避免加法回绕，例如：

```c
void FUNC1(uint32_t idx, uint32_t off)
{
    if (idx >= BUF_SIZE || off >= BUF_SIZE - idx)
        return;
    g_buf[idx] = 0xAA;
}
```

（`BUF_SIZE - idx` 仅在 `idx < BUF_SIZE` 时安全计算，先查 `idx >= BUF_SIZE` 短路保护。）

### 漏洞 TAINT-ba4f59e4

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-ba4f59e4 |
| **类型** | OOB Write（数组越界写） |
| **所在文件** | /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c |
| **所在函数** | FUNC2 |
| **关键行号** | 25 |
| **是否链外** | 否 |

#### 漏洞描述

入口参数 `idx`（uint32）传入形参为 int32 的 FUNC2 时发生隐式符号性翻转：`0xFFFFFFFF` 变为 `-1`。FUNC2 只有 `if (idx >= BUF_SIZE) return;` 上界校验，不拦截负数，`-1` 作为数组下标在 `g_buf` 之前越界写。

#### 漏洞原理

1. 入口函数 `FUNC0(idx, off, len)` 的 `idx` 为 uint32 污点数据。
2. 当 `len == 1` 时，污点 `idx` 传入 `FUNC2(idx)`；FUNC2 形参为 `int32_t idx`，**实参到形参发生隐式 uint32→int32 转换，符号性翻转**（4.2 类型转换）。
3. FUNC2 中执行 `if (idx >= BUF_SIZE) return;`：该检查**存在**，但只查上界不查下界（5.3①"只查上界不查下界"），对 int32 的负数完全无效。
4. 具体绕过输入：`FUNC0(len=1, idx=0xFFFFFFFF)` → 隐式转换为 `-1` → `-1 >= 64` 为假，校验通过；随后 `g_buf[-1]` 在缓冲区起始地址之前写入，越界写。
5. 越界写破坏 `g_buf` 之前的内存数据，造成内存破坏。

**校验点检查**：`idx >= BUF_SIZE` 属 5.2 显式 if 边界检查，覆盖"有校验"；但按 5.3 完备性检查，该上界校验因符号性错配（实参 uint32→形参 int32）不拦截负值，绕过输入（idx=0xFFFFFFFF → -1）已具体给出，判定校验无效。

**门禁三问**：可触发——单次调用 `FUNC0(len=1, idx=0xFFFFFFFF)` 即触发，路径 FUNC0 → FUNC2；未正确校验——校验存在但只查上界，符号性翻转后负数绕过（具体输入已论证）；有安全影响——缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/insufficient_check/test.c:7   FUNC0(len=1, idx=0xFFFFFFFF)()
[2]   :21                    FUNC2()             （uint32 idx 隐式转换为 int32 -1）
[3]   :23                    -1 >= 64 为假，通过上界校验
[4]   :25                    g_buf[idx] = 0xBB  ← 触发点（idx=-1 负索引越界写）
```

#### 关键代码片段

```c
/* test.c:21  形参为 int32，接收 uint32 实参时符号性翻转 */
void FUNC2(int32_t idx)
{
    if (idx >= BUF_SIZE)     /* ← 只查上界不查下界：
                              *   idx=-1（0xFFFFFFFF 隐式转换而来）时
                              *   -1 >= 64 为假，校验被绕过 */
        return;
    g_buf[idx] = 0xBB;       /* ← 危险点：idx=-1 负索引，
                              *   在 g_buf 起始地址之前越界写 */
}
```

#### 修复建议

同时约束上下界，或改用与入口一致的 uint32 形参消除符号性歧义：

```c
void FUNC2(int32_t idx)
{
    if (idx < 0 || idx >= BUF_SIZE)   /* 补上界校验的下界检查 */
        return;
    g_buf[idx] = 0xBB;
}
```

或

```c
void FUNC2(uint32_t idx)              /* 形参改 uint32，与调用方一致 */
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xBB;
}
```
