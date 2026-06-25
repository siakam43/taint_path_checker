/* test_fixtures/scenario_001/npu_driver.c
 *
 * 场景001：NPU驱动 - ioctl入口 → 命令分发 → 内存分配
 * 预期漏洞：TAINT-buf_overflow - idx参数未经校验用作数组索引
 *          链外辅助函数中存在校验绕过
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define NPU_MAX_QUEUES 64
#define NPU_CMD_SUBMIT  0x01
#define NPU_CMD_ALLOC   0x02
#define NPU_CMD_FREE    0x03

struct npu_queue {
    unsigned int id;
    unsigned int priority;
    void *buffer;
    size_t buf_size;
};

struct npu_context {
    struct npu_queue *queues[NPU_MAX_QUEUES];
    unsigned int num_queues;
};

struct npu_submit_args {
    unsigned int queue_id;
    unsigned int data_size;
    unsigned long data_ptr;
};

struct npu_alloc_args {
    unsigned int queue_id;
    unsigned int queue_size;
    unsigned int priority;
};

/* 调用链外函数 - 校验dispatch函数，但存在缺陷 */
static int npu_dispatch_command(struct npu_context *ctx,
                                 unsigned int cmd,
                                 void __user *uargs)
{
    unsigned int queue_id;

    switch (cmd) {
    case NPU_CMD_SUBMIT: {
        struct npu_submit_args args;

        if (copy_from_user(&args, uargs, sizeof(args)))
            return -EFAULT;

        queue_id = args.queue_id;
        /* BUG: queue_id 未校验上界，直接使用 */
        goto do_submit;
    }
    case NPU_CMD_ALLOC: {
        struct npu_alloc_args args;

        if (copy_from_user(&args, uargs, sizeof(args)))
            return -EFAULT;

        /* 分支内有校验 */
        if (args.queue_id >= NPU_MAX_QUEUES)
            return -EINVAL;

        queue_id = args.queue_id;
        goto do_alloc;
    }
    default:
        return -EINVAL;
    }

do_submit:
    /* 标签do_submit：queue_id为污点，直接作为数组索引 */
    if (ctx->queues[queue_id] == NULL)     /* 漏洞点：OOB read */
        return -EINVAL;

    {
        struct npu_queue *q = ctx->queues[queue_id]; /* 漏洞点：OOB read */
        void *tmp_buf;
        unsigned int sz;

        sz = q->buf_size;
        if (sz > 0x100000)
            return -EINVAL;

        tmp_buf = kmalloc(sz, GFP_KERNEL);
        if (!tmp_buf)
            return -ENOMEM;

        memcpy(tmp_buf, q->buffer, sz);
        /* ... submit to hardware ... */
        kfree(tmp_buf);
        return 0;
    }

do_alloc:
    /* 标签do_alloc：queue_id已经过校验，安全 */
    ctx->queues[queue_id] = kzalloc(sizeof(struct npu_queue), GFP_KERNEL);
    if (!ctx->queues[queue_id])
        return -ENOMEM;

    ctx->queues[queue_id]->id = queue_id;
    return 0;
}

/* 入口函数 */
long npu_ioctl_handler(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct npu_context *ctx;
    int ret;

    ctx = filp->private_data;
    if (!ctx)
        return -EINVAL;

    /* cmd 和 arg 均为外部可控污点数据 */
    ret = npu_dispatch_command(ctx, cmd, (void __user *)arg);

    return ret;
}
