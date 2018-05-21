
#include <stdio.h>

void print_hex(unsigned char *buf, unsigned int len) {
	for (unsigned int x = 0; x < len; x++) {
		printf("%.2X", buf[x]);
	}

	printf("\n");
}

