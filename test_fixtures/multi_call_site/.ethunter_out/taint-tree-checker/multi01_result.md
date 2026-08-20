# 污点树分析报告

- **调用树ID**：multi01
- **分析时间**：2026-08-20 15:22
- **结论**：发现 1 个安全漏洞

## 分析情况

- 调用树共 2 条链，均已纳入数据流追踪；调用树未修复（污点传播均落在树内函数）。
- 链1（FUNC0 → FUNC1）、链2（FUNC0 → FUNC2）。
- 按 5.1 逐调用点枚举：FUNC1 共有 4 个调用点（FUNC0 内行11 `FUNC1(idx)`、行12 `FUNC1(off)`；FUNC2 内行26、行27），每个"调用点→使用点"组合独立分析。

## 漏洞列表

### 漏洞 TAINT-6279b391

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-6279b391 |
| **类型** | OOB Write |
| **所在文件** | /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/multi_call_site/test.c |
| **所在函数** | FUNC1 |
| **关键行号** | 17-17 |
| **是否链外** | 否 |

#### 漏洞描述

入口参数 off 未经任何校验即作为数组索引写入全局数组 g_buf，可导致越界写（任意内存破坏）。

#### 漏洞原理

入口函数 FUNC0(idx, off) 的两个参数均为外部污点（uint32_t）。FUNC0 对 idx 执行 `if (idx >= BUF_SIZE) return` 边界校验（行9-10），但该校验只覆盖调用点1（行11 `FUNC1(idx)`）；调用点2（行12 `FUNC1(off)`）的实参 off 未经过任何校验。FUNC1 内 `g_buf[v] = 0xAA`（行17）将形参 v 直接用作 g_buf 的索引。

按 5.1 逐调用点绑定实参并分别检查校验：
- 调用点1（行11）：实参 idx 已校验（`idx >= BUF_SIZE` 上界检查，uint32 无负数，校验完备）→ 该组合安全；
- 调用点2（行12）：实参 off 无任何校验，off 可取 [0, 0xFFFFFFFF] 任意值，off ≥ 64 时越界写 g_buf → 该组合构成漏洞；
- FUNC2 链的两个调用点（行26、行27）：实参 idx、off 均已先经 `>= BUF_SIZE` 校验 → 不构成漏洞。

攻击者传入 off = 0xFFFFFFFF（或任意 ≥ 64 的值）即触发：`g_buf[off] = 0xAA` 写入 g_buf 范围之外，造成全局数据破坏。

#### 攻击路径

```
攻击路径：

[1] /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/multi_call_site/test.c:7  FUNC0()
[2]   :12     FUNC1()  ← 调用点2：FUNC1(off)，实参 off 未校验
[3]   :17     FUNC1()  ← 触发点：g_buf[v] = 0xAA
```

#### 关键代码片段

```c
void FUNC0(uint32_t idx, uint32_t off)
{
    if (idx >= BUF_SIZE)      // 校验 idx：只覆盖调用点1
        return;
    FUNC1(idx);               // 调用点1：实参 idx 已校验 → 安全
    FUNC1(off);               // 调用点2：实参 off 未校验 → 污点进入 FUNC1
}

void FUNC1(uint32_t v)
{
    g_buf[v] = 0xAA;          // 危险使用点：v = off（未校验）时越界写
}
```

#### 修复建议

在调用点2 前对 off 增加与 idx 相同的边界校验：

```c
void FUNC0(uint32_t idx, uint32_t off)
{
    if (idx >= BUF_SIZE)
        return;
    FUNC1(idx);
    if (off >= BUF_SIZE)      /* 新增：覆盖调用点2 */
        return;
    FUNC1(off);
}
```
