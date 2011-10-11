/*
	This file is part of DNSsnarf.  DNSsnarf is free software: you can
	redistribute it and/or modify it under the terms of the GNU General Public
	License as published by the Free Software Foundation, version 2.

	This program is distributed in the hope that it will be useful, but WITHOUT
	ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
	FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
	details.

	You should have received a copy of the GNU General Public License along with
	this program; if not, write to the Free Software Foundation, Inc., 51
	Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

	Copyright Cyso
*/

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
