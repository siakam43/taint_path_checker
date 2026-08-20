#include <stdint.h>

#define BUF_SIZE 64
#define CB_COUNT 22

static uint8_t g_buf[BUF_SIZE];
static void (*g_cbs[CB_COUNT])(uint32_t);   /* 回调表 */

/* 回调 cb_00..cb_17：校验完备 → 净化（上限内，逐一追踪） */
static void cb_00(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x00; }
static void cb_01(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x01; }
static void cb_02(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x02; }
static void cb_03(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x03; }
static void cb_04(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x04; }
static void cb_05(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x05; }
static void cb_06(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x06; }
static void cb_07(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x07; }
static void cb_08(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x08; }
static void cb_09(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x09; }
static void cb_10(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0A; }
static void cb_11(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0B; }
static void cb_12(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0C; }
static void cb_13(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0D; }
static void cb_14(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0E; }
static void cb_15(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x0F; }
static void cb_16(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x10; }
static void cb_17(uint32_t idx) { if (idx >= BUF_SIZE) return; g_buf[idx] = 0x11; }
static void cb_18(uint32_t idx) { g_buf[0] = 0xEE; }   /* 不使用 idx → 停止传播 */
static void cb_19(uint32_t idx) { g_buf[idx] = 0x13; } /* 无校验 → 漏洞1（上限内） */
static void cb_20(uint32_t idx) { g_buf[idx] = 0x14; } /* 无校验 → 超限：仅列出，不补链、不报告 */
static void cb_21(uint32_t idx) { g_buf[idx] = 0x15; } /* 无校验 → 超限：仅列出，不补链、不报告 */

void init_reg(void)                                   /* 注册点（供间接调用解析搜索） */
{
    g_cbs[0] = cb_00; g_cbs[1] = cb_01; g_cbs[2] = cb_02; g_cbs[3] = cb_03;
    g_cbs[4] = cb_04; g_cbs[5] = cb_05; g_cbs[6] = cb_06; g_cbs[7] = cb_07;
    g_cbs[8] = cb_08; g_cbs[9] = cb_09; g_cbs[10] = cb_10; g_cbs[11] = cb_11;
    g_cbs[12] = cb_12; g_cbs[13] = cb_13; g_cbs[14] = cb_14; g_cbs[15] = cb_15;
    g_cbs[16] = cb_16; g_cbs[17] = cb_17; g_cbs[18] = cb_18; g_cbs[19] = cb_19;
    g_cbs[20] = cb_20; g_cbs[21] = cb_21;
}

void func_after(uint32_t idx)                          /* 扇出后的直接调用：无校验 → 漏洞2 */
{
    g_buf[idx] = 0xFF;
}

void func_disp(uint32_t ver, uint32_t idx)             /* 入口 */
{
    if (ver < CB_COUNT)
        g_cbs[ver](idx);                              /* 扇出分发点 */
    func_after(idx);                                  /* 扇出之外的独立分支——验证"截断≠终止" */
}
