#include <stdint.h>

#define BUF_SIZE 64

static uint8_t g_buf[BUF_SIZE];

void FUNC0(uint32_t idx, uint32_t off, uint32_t len)
{
    if (len == 0)      FUNC1(idx, off);   /* 链1 */
    else if (len == 1) FUNC2(idx);        /* 链2 */
    else               FUNC3(len);        /* 链3 */
}

void FUNC1(uint32_t idx, uint32_t off)    /* 案例1：整数回绕绕过 */
{
    if (idx + off >= BUF_SIZE)            /* 校验表达式本身溢出 */
        return;
    g_buf[idx] = 0xAA;                    /* idx=UINT32_MAX, off=2 → 回绕通过 → OOB */
}

void FUNC2(int32_t idx)                   /* 案例2：只查上界，负数绕过 */
{
    if (idx >= BUF_SIZE)
        return;
    g_buf[idx] = 0xBB;                    /* idx=-1 → OOB */
}

void FUNC3(uint32_t len)                  /* 案例3：对照——校验完备，不应报 */
{
    if (len >= BUF_SIZE)
        return;
    g_buf[len] = 0xCC;                    /* uint32 无负数，上界检查即完备 */
}
