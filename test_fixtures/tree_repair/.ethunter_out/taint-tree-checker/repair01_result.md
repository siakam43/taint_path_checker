# 污点树分析报告

- **调用树ID**：repair01
- **分析时间**：2026-08-18 16:40:00
- **结论**：发现 1 个安全漏洞

## 分析情况

调用树共含 2 条链（入口函数 func_dispatch，参数 `cmd`、`idx` 均为外部输入），修复后均已纳入数据流追踪：

- **链1（func_dispatch → func_branch_a → func_indirect）**：入口参数 `cmd==0` 时进入。污点 `idx` 经 func_branch_a 原样传递，func_branch_a 内通过函数指针 `g_cb = func_indirect; g_cb(idx)` 间接调用 func_indirect（原输入树在 func_branch_a 处提前中断，无法直接看到该调用关系）；func_indirect 中 `idx` 直接作为全局数组 `g_buf[BUF_SIZE=16]` 的下标写入，**无任何校验**，存在越界写漏洞。
- **链2（func_dispatch → func_branch_b）**：入口参数 `cmd!=0` 时进入（原输入树缺失该分支链，修复补充）。func_branch_b 先对 `idx` 执行 `if (idx < BUF_SIZE)` 上界校验，校验通过后才写入 `g_buf[idx]`，`idx` 被净化，**无漏洞**。

**调用树修复情况**：输入树含 1 条链且存在两处缺陷，修复如下——

1. **延伸链1（调用链提前中断）**：链1在 func_branch_a 处中断（`g_cb(idx)` 间接调用）。在 project_dir 中解析函数指针 `g_cb` 的赋值点 `g_cb = func_indirect`（test.c 第 19 行），目标唯一确定为 `func_indirect`，污点 `idx` 经该调用继续传播，故将链1延伸为 func_dispatch → func_branch_a → func_indirect。
2. **补充链2（调用链缺失）**：入口函数 `cmd != 0` 分支将污点 `idx` 传入 func_branch_b，该调用关系不在输入树内，从入口函数补写完整新链 func_dispatch → func_branch_b。
3. **未补入 func_helper（非污点调用关系）**：func_branch_b 内调用 `func_helper(0)` 实参为常量 0，未传递任何污点数据，按"仅污点驱动"规则该调用关系不补入树，防止路径爆炸。
4. **g_cb 非污点数据**：`g_cb` 虽为全局函数指针，但其写入值为函数地址（非外部输入数据），仅作为间接调用目标，不构成全局污点传播。

修复后调用树已写入 `test_fixtures/tree_repair/.ethunter_out/taint-tree-checker/repair01_tree_fixed.json`，输入文件 `repair01.json` 未被修改。

**污点状态追踪**：`idx`（链1）→ 经 func_branch_a 间接调用到达 func_indirect 危险使用点（未校验）；`idx`（链2）→ func_branch_b 中 `idx < BUF_SIZE` 校验后净化，随后无害消费；`cmd` → 仅用于 if 分支分发，被分支选择消费；`func_helper` 参数为常量，不接触污点。全部污点变量均达终态（停止传播/被净化/到达危险使用点），无"无法追踪"分支。

## 漏洞列表

### 漏洞 TAINT-79c4b629

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-79c4b629 |
| **类型** | Buffer Overflow（数组越界写，OOB Write） |
| **所在文件** | /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/tree_repair/test.c |
| **所在函数** | func_indirect |
| **关键行号** | 25 |
| **是否链外** | 否 |

#### 漏洞描述

外部输入 `idx` 经链1（func_dispatch → func_branch_a → 间接调用 func_indirect）未经任何校验到达 func_indirect，直接作为全局数组 `g_buf[16]` 的下标写入 `g_buf[idx] = 0x55`，攻击者可通过构造入口参数 `cmd=0`、`idx` 为任意大值，实现全局缓冲区越界写，破坏相邻全局数据（如 `g_buf` 之后的静态存储区）。

#### 漏洞原理

1. 入口函数 `func_dispatch(cmd, idx)` 的两个参数均为外部输入，其中 `idx` 为污点数据。
2. 当 `cmd == 0` 时，func_dispatch 将污点 `idx` 原样传入 `func_branch_a(idx)`。
3. func_branch_a 中执行 `g_cb = func_indirect;` 将函数指针 `g_cb` 指向 func_indirect，随后 `g_cb(idx)` 将污点 `idx` 原样传入 func_indirect（间接调用，原调用树在此处中断，已按函数指针赋值点解析目标并延伸链1）。
4. func_indirect 中执行 `g_buf[idx] = 0x55`：污点 `idx`（`uint32_t`）直接作为下标索引全局数组 `g_buf`（大小 `BUF_SIZE = 16`），此前从入口到漏洞点（func_dispatch → func_branch_a → func_indirect）无 `idx < BUF_SIZE` 之类的任何上界校验。
5. 越界写可覆盖 `g_buf` 之后的全局数据，造成内存破坏。

**校验点检查**：从入口到漏洞点，对 `idx` 无显式边界检查、无隐式校验（无掩码、无类型窄化、无 switch/if-else 值过滤）；`if (cmd == 0)` 仅约束分支选择，不约束 `idx` 的取值。故该漏洞满足"未校验"门禁。

**门禁三问**：可触发——单次调用 `func_dispatch(cmd=0, idx=任意大值)` 即可触发，路径 func_dispatch → func_branch_a →（函数指针 g_cb 间接调用）→ func_indirect；未校验——`idx` 到达 `g_buf[idx]` 前无任何显式/隐式校验；有安全影响——全局缓冲区越界写，内存破坏。三问均通过，上报。

#### 攻击路径

```
攻击路径：

[1] /home/admin/cc/wksp/siakam_security_skills/taint_path_checker/test_fixtures/tree_repair/test.c:8   func_dispatch(cmd=0, idx=0x80000000)()
[2]   :11                    func_branch_a()
[3]   :19                    g_cb = func_indirect; g_cb(idx)（函数指针间接调用，污点 idx 传递）
[4]   :25                    func_indirect()  ← 触发点（g_buf[idx] = 0x55，idx 无校验）
```

#### 关键代码片段

```c
/* test.c:8  入口函数，cmd、idx 均为外部输入 */
void func_dispatch(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {
        func_branch_a(idx);      /* 污点 idx 沿链1传递 */
    } else {
        func_branch_b(idx);      /* 污点 idx 沿链2传递（树外分支，修复补链） */
    }
}

/* test.c:17 */
void func_branch_a(uint32_t idx)
{
    g_cb = func_indirect;        /* 函数指针赋值，间接调用目标解析为 func_indirect */
    g_cb(idx);                   /* 间接调用，污点 idx 继续传递（链1延伸） */
}

/* test.c:23 */
void func_indirect(uint32_t idx)
{
    g_buf[idx] = 0x55;           /* ← 危险点：污点 idx 作数组下标，无上界校验，
                                  *   g_buf 仅 16 字节（BUF_SIZE=16），idx 为任意 uint32_t 值 */
}
```

#### 修复建议

在污点下标使用前增加上界校验，例如在 func_indirect 入口处校验（或参照链2中 func_branch_b 的既有做法）：

```c
void func_indirect(uint32_t idx)
{
    if (idx >= BUF_SIZE)         /* 增加上界校验，与 func_branch_b 一致 */
        return;
    g_buf[idx] = 0x55;
}
```

或统一在入口函数 func_dispatch 分发前对 `idx` 校验后再进入各分支，保证所有使用路径均被覆盖。

## 各链覆盖结论

- **链1（func_dispatch → func_branch_a → func_indirect）**：已纳入数据流追踪（修复：延伸——间接调用目标 func_indirect 经函数指针赋值点解析确定）。
- **链2（func_dispatch → func_branch_b）**：已纳入数据流追踪（修复：补充——cmd!=0 分支调用关系缺失，从入口函数补写完整新链）。

该调用树的外部输入经修复后的调用树追踪，在链2 关键使用点前经过校验，但链1 中 func_indirect 的 `g_buf[idx]` 使用点前未校验，存在可被利用的越界写漏洞。
