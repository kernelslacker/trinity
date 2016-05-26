/*
 * Pick a testfile, truncate it back to zero bytes, or a
 * selection of random sizes.
 */

#include <sys/types.h>
#include <unistd.h>
#include "objects.h"
#include "random.h"
#include "testfile.h"
#include "utils.h"

//TODO: stat the file, and divide by two

bool truncate_testfile(struct childdata *child)
{
	int fd;
	int ret;
	off_t sizes[] = { 0, 4096, MB(1), GB(1) };

	fd = get_rand_testfile_fd();
	if (fd < 0)
		return FALSE;

	ret = ftruncate(fd, RAND_ARRAY(sizes));

	clock_gettime(CLOCK_MONOTONIC, &child->tp);

	if (ret < 0)
		return FALSE;

	return TRUE;
}
