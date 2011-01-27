#ifndef __HELPER_H__
#define __HELPER_H__

#include "types.h"

void hexdump(void *ptr, int buflen);

u16 be16(u8 *p);
u32 be32(u8 *p);

#endif
