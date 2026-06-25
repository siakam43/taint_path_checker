/* test_fixtures/scenario_003/bl2_image_loader.c
 *
 * 场景003：BL2启动链 - 镜像头解析
 * 预期漏洞：TAINT-img_overflow - 自定义hw_mem_copy函数语义等同于memcpy，
 *          img_size来自外部镜像头，未经校验用作拷贝长度
 * 关注点：自定义封装函数识别（hw_mem_copy语义等同于memcpy）
 *         整数溢出：img_size + offset可能回绕
 */

#include <stdint.h>
#include <string.h>

#define BL2_LOAD_BASE  0x80000000
#define BL2_MAX_SIZE   0x100000
#define BL2_IMG_MAGIC  0x424C3249

struct fip_header {
    uint32_t magic;
    uint32_t img_size;
    uint32_t img_offset;
    uint32_t entry_point;
    uint32_t flags;
};

struct bl2_ctx {
    uint8_t *load_buffer;
    uint32_t buf_capacity;
};

/* 自定义封装函数 - 语义等同于memcpy */
static void hw_mem_copy(void *dst, const void *src, uint32_t n)
{
    uint32_t i;
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;

    for (i = 0; i < n; i++)
        d[i] = s[i];           /* 循环内的逐字节拷贝 */
}

/* 链外函数：从存储设备读取镜像头 */
static int bl2_read_header(struct fip_header *hdr, uint32_t offset)
{
    /* 模拟从外部存储读取FIP头 */
    /* hdr->img_size在此函数内被外部数据填充 */
    memset(hdr, 0, sizeof(*hdr));
    hdr->img_size = 0x200000;  /* 模拟：外部存储中的值，超过BL2_MAX_SIZE */
    hdr->img_offset = 0x1000;
    hdr->entry_point = BL2_LOAD_BASE;
    return 0;
}

/* 入口函数 - BL2镜像加载 */
int bl2_load_image(struct bl2_ctx *ctx, uint32_t storage_offset)
{
    struct fip_header hdr;
    uint32_t total_size;
    int ret;

    ret = bl2_read_header(&hdr, storage_offset);
    if (ret != 0)
        return -1;

    /* 魔数校验 */
    if (hdr.magic != BL2_IMG_MAGIC)
        return -1;

    /* BUG: img_size未校验上界 */
    /* BUG: total_size = img_size + img_offset 可能整数溢出 */
    total_size = hdr.img_size + hdr.img_offset;   /* 漏洞：整数溢出 */

    if (total_size > ctx->buf_capacity) {
        /* 仅校验total_size，但若total_size溢出为小值则绕过此检查 */
        return -1;
    }

    /* BUG: 使用自定义hw_mem_copy(语义同memcpy)，拷贝未校验的img_size字节 */
    hw_mem_copy(ctx->load_buffer, (void *)(BL2_LOAD_BASE + hdr.img_offset),
                hdr.img_size);                     /* 漏洞：缓冲区溢出 */

    return 0;
}
