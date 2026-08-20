#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];

void FUNC0(uint32_t idx, uint32_t off)
{
    if (idx >= BUF_SIZE)      /* 校验 idx：只覆盖调用点1 */
        return;
    FUNC1(idx);               /* 调用点1：实参已校验 */
    FUNC1(off);               /* 调用点2：实参未校验 → 漏洞经此触发 */
}

void FUNC1(uint32_t v)
{
    g_buf[v] = 0xAA;          /* 危险使用点 */
}

void FUNC2(uint32_t idx, uint32_t off)  /* 对照链：两个调用点均已校验 */
{
    if (idx >= BUF_SIZE)
        return;
    if (off >= BUF_SIZE)
        return;
    FUNC1(idx);
    FUNC1(off);
}
