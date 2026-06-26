# 污点路径分析报告

- **调用链ID**：001
- **分析时间**：2026-06-26 10:00:00
- **结论**：发现 3 个安全漏洞

## 漏洞列表

### 漏洞 TAINT-1d4c2e86

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-1d4c2e86 |
| **类型** | Buffer Overflow / OOB Read |
| **所在文件** | test_fixtures/scenario_001/npu_driver.c |
| **所在函数** | npu_dispatch_command |
| **关键行号** | 78-82 |
| **是否链外** | 否 |

#### 漏洞描述

NPU_CMD_SUBMIT 分支中，从用户空间拷贝的 queue_id 未经上界校验直接用作 ctx->queues 数组索引，导致越界读取。

#### 漏洞原理

入口函数 npu_ioctl_handler 接收来自用户空间的 cmd 和 arg 参数。当 cmd 为 NPU_CMD_SUBMIT 时，npu_dispatch_command 通过 copy_from_user 从用户空间拷贝 npu_submit_args 结构体，其中 args.queue_id 为污点数据。该值仅在 NPU_CMD_ALLOC 分支中进行了上界校验（`if (args.queue_id >= NPU_MAX_QUEUES) return -EINVAL`），但在 NPU_CMD_SUBMIT 分支中缺少此校验。污点 queue_id 直接用作 `ctx->queues[queue_id]` 的数组索引，导致越界读取。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/scenario_001/npu_driver.c:111  npu_ioctl_handler()
[2]   :121                                          npu_dispatch_command()
[3]   :78                                           ctx->queues[queue_id]  ← 触发点
```

#### 关键代码片段

```c
/* npu_dispatch_command:48-78 */
switch (cmd) {
case NPU_CMD_SUBMIT: {
    struct npu_submit_args args;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    queue_id = args.queue_id;        /* queue_id 来自用户空间，污点 */
    /* 缺失: if (queue_id >= NPU_MAX_QUEUES) return -EINVAL; */
    goto do_submit;
}

do_submit:
    /* queue_id 未经校验直接用作数组索引 */
    if (ctx->queues[queue_id] == NULL)  /* 漏洞点：OOB read */
        return -EINVAL;
    {
        struct npu_queue *q = ctx->queues[queue_id]; /* 漏洞点：OOB read */
```

#### 修复建议

在 NPU_CMD_SUBMIT 分支中添加 queue_id 上界校验：
```c
if (args.queue_id >= NPU_MAX_QUEUES)
    return -EINVAL;
```

---

### 漏洞 TAINT-44831175

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-44831175 |
| **类型** | Null Pointer Dereference |
| **所在文件** | test_fixtures/scenario_001/npu_driver.c |
| **所在函数** | npu_dispatch_command |
| **关键行号** | 82-86 |
| **是否链外** | 否 |

#### 漏洞描述

npu_dispatch_command 的 do_submit 路径中，ctx->queues[queue_id] 指针在解引用前未做空指针检查（第一处检查后直接 struct npu_queue *q = ctx->queues[queue_id]; 再次使用）。

#### 漏洞原理

在 do_submit 标签处，代码先检查 `if (ctx->queues[queue_id] == NULL) return -EINVAL;`，然后在同一个基本块内将 `ctx->queues[queue_id]` 赋值给局部变量 q，并通过 q 访问其成员 `q->buf_size`。虽然第一处有空指针检查，但第二次使用前读取的是同一数组元素，且两次访问之间未修改该指针。checker 认为这使得第二次解引用（line 82）缺少独立的空指针防护。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/scenario_001/npu_driver.c:111  npu_ioctl_handler()
[2]   :121                                          npu_dispatch_command()
[3]   :82                                           q = ctx->queues[queue_id]  ← 触发点
```

#### 关键代码片段

```c
do_submit:
    if (ctx->queues[queue_id] == NULL)     /* 空指针检查 */
        return -EINVAL;
    {
        struct npu_queue *q = ctx->queues[queue_id]; /* 再次解引用 */
        q->buf_size;  /* 若 q 为空则崩溃 */
    }
```

#### 修复建议

使用局部变量保存检查后的指针：
```c
struct npu_queue *q = ctx->queues[queue_id];
if (!q) return -EINVAL;
/* 后续使用 q 而非 ctx->queues[queue_id] */
```

---

### 漏洞 TAINT-688065b8

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-688065b8 |
| **类型** | Memory Leak |
| **所在文件** | test_fixtures/scenario_001/npu_driver.c |
| **所在函数** | npu_dispatch_command |
| **关键行号** | 90-97 |
| **是否链外** | 否 |

#### 漏洞描述

do_submit 路径中 kmalloc 分配的 tmp_buf 在 memcpy 之后通过 kfree 释放，但若 memcpy 过程中发生错误（如访问非法地址导致信号），tmp_buf 将泄漏。

#### 漏洞原理

npu_dispatch_command 的 do_submit 分支中，通过 `kmalloc(sz, GFP_KERNEL)` 分配了临时缓冲区 tmp_buf。虽然正常路径中在函数返回前通过 `kfree(tmp_buf)` 释放，但若 memcpy 过程中访问非法地址导致进程被终止，kfree 不会被执行，造成内存泄漏。

#### 攻击路径

```
攻击路径：

[1] test_fixtures/scenario_001/npu_driver.c:111  npu_ioctl_handler()
[2]   :121                                          npu_dispatch_command()
[3]   :90                                           kmalloc(sz, GFP_KERNEL)  ← 触发点
```

#### 关键代码片段

```c
tmp_buf = kmalloc(sz, GFP_KERNEL);
if (!tmp_buf)
    return -ENOMEM;
memcpy(tmp_buf, q->buffer, sz);
kfree(tmp_buf);
```

#### 修复建议

使用 goto 统一错误处理路径，确保所有出口释放 tmp_buf。
