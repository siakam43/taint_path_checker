# 污点树分析报告

- **调用树ID**：fanout_limit01
- **分析时间**：2026-08-20 16:55
- **结论**：发现 2 个安全漏洞

## 分析情况

- 调用树共 1 条链（func_disp），已纳入数据流追踪。
- 调用树修复情况：输入链在 func_disp 处中断，经间接调用解析（注册点 init_reg，test.c:33）确定回调表 g_cbs 共注册 22 个目标，超过单分发点扇出上限（20），按注册顺序取前 20 个（cb_00..cb_19）补链并逐一追踪；同时按"截断≠终止"规则继续追踪扇出之外的直接调用分支 func_after。修复后共补入 21 条链，落盘至 fanout_limit01_tree_fixed.json。
- 扇出逐回调结论：
  - cb_00..cb_17（test.c:10-27）：接收污点 idx；`idx >= BUF_SIZE` 校验完备 → 净化
  - cb_18（test.c:28）：接收污点 idx 但未使用（写 g_buf[0] 常量）→ 停止传播
  - cb_19（test.c:29）：接收污点 idx；无校验 → 到达危险使用点（漏洞1）
  - cb_20（test.c:30）、cb_21（test.c:31）：超出扇出上限（20），按规则不追踪、不补链，仅在此列出
  - func_after（test.c:43）：扇出之外的直接调用分支，接收污点 idx；无校验 → 到达危险使用点（漏洞2）

## 漏洞列表

### 漏洞 TAINT-3ecf115e

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-3ecf115e |
| **类型** | OOB Write |
| **所在文件** | test_fixtures/fanout_limit/test.c |
| **所在函数** | cb_19 |
| **关键行号** | 29-29 |
| **是否链外** | 否 |

#### 漏洞描述

注册回调 cb_19 将入口污点 idx 直接用作全局数组 g_buf 的索引，无任何校验，可越界写。

#### 漏洞原理

入口 func_disp(ver, idx) 的参数均为外部污点。func_disp 经 `g_cbs[ver](idx)` 间接分发（注册点 init_reg，test.c:33），ver=19 时调用 cb_19。cb_19 内 `g_buf[idx] = 0x13`（行29）无任何边界校验，idx 可取 [0, 0xFFFFFFFF]，idx ≥ 64 时越界写 g_buf。cb_00..cb_17 均有 `idx >= BUF_SIZE` 校验（净化），cb_19 无校验，校验结论按回调独立。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/fanout_limit/test.c:48  func_disp()
[2]   :51     func_disp()  ← g_cbs[ver](idx)，ver=19 → cb_19
[3]   :29     cb_19()  ← 触发点：g_buf[idx] = 0x13
```

#### 关键代码片段

```c
static void cb_19(uint32_t idx) { g_buf[idx] = 0x13; } /* 无校验 → OOB Write */

void func_disp(uint32_t ver, uint32_t idx)
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);          /* ver=19 → cb_19，idx 未校验 */
}
```

#### 修复建议

在 cb_19 内增加边界校验：`if (idx >= BUF_SIZE) return;`（与 cb_00..cb_17 一致）。

### 漏洞 TAINT-471514e7

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-471514e7 |
| **类型** | OOB Write |
| **所在文件** | test_fixtures/fanout_limit/test.c |
| **所在函数** | func_after |
| **关键行号** | 45-45 |
| **是否链外** | 否 |

#### 漏洞描述

func_disp 在扇出分发之后直接调用 func_after，后者将污点 idx 直接用作 g_buf 索引，无校验，可越界写。

#### 漏洞原理

按 4.3.2"截断≠终止"规则：扇出上限截断只影响回调分支，func_disp 中扇出之后的独立分支 func_after(idx)（行52）必须继续追踪。func_after 内 `g_buf[idx] = 0xFF`（行45）无任何校验，idx ≥ 64 时越界写 g_buf。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/fanout_limit/test.c:48  func_disp()
[2]   :52     func_disp()  ← func_after(idx)，扇出之后的独立分支
[3]   :45     func_after()  ← 触发点：g_buf[idx] = 0xFF
```

#### 关键代码片段

```c
void func_after(uint32_t idx)
{
    g_buf[idx] = 0xFF;      /* 无校验 → OOB Write */
}
```

#### 修复建议

在 func_after 内增加边界校验：`if (idx >= BUF_SIZE) return;`。
