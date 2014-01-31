#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

void * zmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p == NULL) {
		printf("malloc(%zu) failure.\n", size);
		exit(EXIT_FAILURE);
	}

	memset(p, 0, size);
	return p;
}

void sizeunit(unsigned long size, char *buf)
{
	if (size < 1024 * 1024) {
		sprintf(buf, "%ld bytes", size);
		return;
	}

	if (size < (1024 * 1024 * 1024)) {
		sprintf(buf, "%ldMB", (size / 1024) / 1024);
		return;
	}

	sprintf(buf, "%ldGB", ((size / 1024) / 1024) / 1024);
}
