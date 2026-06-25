/* test_fixtures/scenario_002/isp_firmware.c
 *
 * 场景002：ISP固件 - 共享内存IPC消息处理
 * 预期漏洞：TAINT-oob_write - msg_hdr经过了魔数校验，但payload_len字段未被校验
 *          校验了version但不代表校验了data字段
 * 关注点：结构体成员级别的污染区分，部分字段校验不能代表整体
 */

#include <stdint.h>
#include <string.h>

#define ISP_MSG_MAGIC 0x4953504D
#define ISP_MAX_PAYLOAD 4096
#define ISP_OUTPUT_BUF_SIZE 2048

struct isp_msg_header {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_len;
    uint32_t cmd_id;
};

struct isp_msg {
    struct isp_msg_header hdr;
    uint8_t payload[ISP_MAX_PAYLOAD];
};

struct isp_ctx {
    uint8_t output_buf[ISP_OUTPUT_BUF_SIZE];
    struct isp_msg *shm_msg;  /* 指向共享内存的消息 */
};

/* 链外辅助函数：从共享内存解析消息头 */
static int isp_parse_header(struct isp_msg_header *hdr, struct isp_msg *msg)
{
    /* 共享内存数据拷贝到本地 */
    memcpy(hdr, &msg->hdr, sizeof(*hdr));

    /* 只有魔数校验，没有校验 payload_len */
    if (hdr->magic != ISP_MSG_MAGIC)
        return -1;

    /* version字段的校验不关联payload安全 */
    if (hdr->version < 2)
        return -1;

    return 0;
}

/* 链外辅助函数：处理payload */
static void isp_process_cmd_v2(struct isp_ctx *ctx, uint8_t *payload, uint32_t len)
{
    uint32_t copy_len;

    /* len来自未经校验的payload_len，且本函数内部也未校验 */
    copy_len = len;                         /* 污点传播：len -> copy_len */

    if (copy_len > 0)
        memcpy(ctx->output_buf, payload, copy_len); /* 漏洞点：output_buf大小仅2048，
                                                        copy_len可达4096，造成栈/全局溢出 */
}

/* 调用链入口函数 - ISP消息处理入口 */
int isp_handle_msg(struct isp_ctx *ctx)
{
    struct isp_msg_header hdr;
    int ret;

    /* ctx->shm_msg来自共享内存(另一协处理器)，视为外部输入 */
    ret = isp_parse_header(&hdr, ctx->shm_msg);
    if (ret != 0)
        return -1;

    /* hdr已经过魔数和版本校验，但hdr.payload_len未被校验 */
    /* hdr其他字段的校验不等于hdr.payload_len被校验 */

    switch (hdr.cmd_id) {
    case 1:
        /* ... 处理命令1 ... */
        break;
    case 2:
        isp_process_cmd_v2(ctx, ctx->shm_msg->payload, hdr.payload_len);
        break;
    default:
        break;
    }

    return 0;
}
