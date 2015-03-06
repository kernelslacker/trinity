#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

#define MAX_PATH_LEN 4096

const char * generate_pathname(void)
{
	const char *pathname = get_filename();
	char *newpath;
	unsigned int len;

	if (pathname == NULL)		/* handle -n correctly. */
		return NULL;

	/* 90% chance of returning an unmangled filename */
	if (!ONE_IN(10))
		return pathname;

	/* Create a bogus filename. */
	newpath = zmalloc(MAX_PATH_LEN);	// FIXME: We leak this.

	len = strlen(pathname);

	if (rand_bool())
		(void) strncpy(newpath, pathname, len);
	else {
		if (len < MAX_PATH_LEN - 2) {
			/* make it look relative to cwd */
			newpath[0] = '.';
			newpath[1] = '/';
			(void) strncpy(newpath + 2, pathname, len);
		}
	}

	/* 50/50 chance of making it look like a dir */
	if (rand_bool()) {
		if (len <= MAX_PATH_LEN - 2) {
			newpath[len] = '/';
			newpath[len + 1] = 0;
		}
	}

	return newpath;
}
