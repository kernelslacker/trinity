#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "files.h"

static char * filebuffer = NULL;
unsigned long filebuffersize = 0;

/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_read(
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__attribute((unused)) unsigned long *a4,
		__attribute((unused)) unsigned long *a5,
		__attribute((unused)) unsigned long *a6)
{
	unsigned long newsize = ((unsigned int) *a3) >>8;

	*a1 = get_random_fd();

	if (filebuffer != NULL) {
		if (filebuffersize < newsize) {
			free(filebuffer);
			filebuffersize = 0;
		}
	}

	if (filebuffer == NULL) {
retry:
		printf("Trying to allocate %lu bytes\n", newsize);
		filebuffer = malloc(newsize);
		if (filebuffer == NULL) {
			newsize >>= 1;
			goto retry;
		}
		filebuffersize = newsize;
	}
	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
}

/*
 * asmlinkage ssize_t sys_write(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_write(
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__attribute((unused)) unsigned long *a4,
		__attribute((unused)) unsigned long *a5,
		__attribute((unused)) unsigned long *a6)
{
	unsigned long newsize = *a3 & 0xffff;
	void *newbuffer;

	*a1 = get_random_fd();

retry:
	newbuffer = malloc(newsize);
	if (newbuffer == NULL) {
		newsize >>= 1;
		goto retry;
	}

	free(filebuffer);
	filebuffer = newbuffer;
	filebuffersize = newsize;

	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
}

/*
 * asmlinkage long sys_splice(int fdin, int fdout, size_t len, unsigned int flags)
 * : len must be > 0
 * : fdin & fdout must be file handles
 *
 */
void sanitise_splice(
		unsigned long *a1,
		unsigned long *a2,
		__attribute((unused)) unsigned long *a3,
		__attribute((unused)) unsigned long *a4,
		__attribute((unused)) unsigned long *a5,
		__attribute((unused)) unsigned long *a6)
{
	/* first param is fdin */
	*a1 = get_random_fd();

	/* second param is fdout */
	*a2 = get_random_fd();

	/* Returns 0 if !len */
retry:
	if (*a3 == 0) {
		*a3 = rand();
		goto retry;
	}
}
