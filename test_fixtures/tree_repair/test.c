#include <stdint.h>

#define BUF_SIZE 16

static uint8_t g_buf[BUF_SIZE];
static void (*g_cb)(uint32_t);

void func_dispatch(uint32_t cmd, uint32_t idx)
{
    if (cmd == 0) {
        func_branch_a(idx);
    } else {
        func_branch_b(idx);
    }
}

void func_branch_a(uint32_t idx)
{
    g_cb = func_indirect;
    g_cb(idx);
}

void func_indirect(uint32_t idx)
{
    g_buf[idx] = 0x55;
}

void func_branch_b(uint32_t idx)
{
    func_helper(0);
    if (idx < BUF_SIZE)
        g_buf[idx] = 0xAA;
}

void func_helper(uint32_t x)
{
    (void)x;
}
