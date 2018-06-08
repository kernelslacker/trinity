//TODO: eventually this file will go away, and we'll just share parts of
// the top-level utils.c

#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

void * __zmalloc(size_t size, const char *func)
{
	void *p;

	p = malloc(size);
	if (p == NULL) {
		/* Maybe we mlockall'd everything. Try and undo that, and retry. */
		munlockall();
		p = malloc(size);
		if (p != NULL)
			goto done;

		printf("%s: malloc(%zu) failure.\n", func, size);
		exit(EXIT_FAILURE);
	}

done:
	memset(p, 0, size);
	return p;
}
