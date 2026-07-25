#include <stdint.h>

#if FEATURE_X
static int vuln_handler(uint32_t idx)
{
    uint8_t buf[16];
    buf[idx] = 0;  // potential OOB write, idx from external input
    return 0;
}
#endif

int entry_func(uint32_t user_idx)
{
#if FEATURE_X
    return vuln_handler(user_idx);
#else
    return -1;
#endif
}
