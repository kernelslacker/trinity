#include <execinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"

void show_backtrace(void)
{
	int j, nptrs;
#define SIZE 100
	void *buffer[100];
	char **strings;

	nptrs = backtrace(buffer, SIZE);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}

	for (j = 0; j < nptrs; j++)
		printf("%s\n", strings[j]);

	free(strings);
}

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
