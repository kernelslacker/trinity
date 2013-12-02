#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

void * zmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p == NULL) {
		printf("malloc(%ld) failure.\n", size);
		exit(EXIT_FAILURE);
	}

	memset(p, 0, size);
	return p;
}
