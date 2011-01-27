#include <stdio.h>
#include <ctype.h>

#include "types.h"

void hexdump(void *ptr, int buflen) {
	u8 *buf = (u8*)ptr;
	int i, j;

	for (i=0; i<buflen; i+=16) {
		printf("%06x: ", i);
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%02x ", buf[i+j]);
			else
				printf("   ");

		printf(" ");
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');

		printf("\n");
	}
}

u16 be16(u8 *p) {
	return (p[0] << 8) | p[1];
}

u32 be32(u8 *p) {
	return (
		(p[0] << 24) |
		(p[1] << 16) |
		(p[2] <<  8) |
		p[3]
	);
}
