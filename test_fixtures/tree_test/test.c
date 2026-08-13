#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];
static uint32_t g_flag;

void FUNC0(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {
        FUNC1(idx);
    } else {
        FUNC3(idx);
    }
}

void FUNC1(uint32_t idx)
{
    g_flag = idx;               /* 链1写入全局变量 */
    FUNC2(idx);
}

void FUNC2(uint32_t idx)
{
    g_buf[idx] = 0xAA;          /* 链1：idx 未校验 */
}

void FUNC3(uint32_t idx)
{
    if (idx >= BUF_SIZE)        /* 链2：idx 已校验 */
        return;
    g_buf[g_flag] = 0xCC;       /* 链2内 g_flag 未被污染（链间独立） */
}
