#include <stdint.h>

#define BUF_SIZE 64
#define CB_COUNT 4

static uint8_t g_buf[BUF_SIZE];
static void (*g_cbs[CB_COUNT])(uint32_t);   /* 回调表 */

static void cb_a(uint32_t idx) {            /* 回调1：校验完备 → 不应报 */
    if (idx >= BUF_SIZE) return;
    g_buf[idx] = 0xAA;
}

static void cb_b(uint32_t idx) {            /* 回调2：无校验 → 漏洞1 */
    g_buf[idx] = 0xBB;
}

static void cb_c(uint32_t idx) {            /* 回调3：传递污点到树外 helper → 漏洞2 */
    helper_write(idx);                      /* 深一层，验证补链 */
}

static void helper_write(uint32_t idx) {    /* 树外辅助函数 */
    g_buf[idx] = 0xCC;                      /* 无校验 */
}

static void cb_d(uint32_t idx) {            /* 回调4：不使用 idx */
    g_buf[0] = 0xDD;
}

void init_reg(void) {                       /* 注册点（供间接调用解析搜索） */
    g_cbs[0] = cb_a; g_cbs[1] = cb_b;
    g_cbs[2] = cb_c; g_cbs[3] = cb_d;
}

void func_disp(uint32_t ver, uint32_t idx)  /* 入口 */
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);                    /* 间接调用扇出，输入树在此中断 */
}
