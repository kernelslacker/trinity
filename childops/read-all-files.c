/*
 * Simple child to iterate over the entire fd list, opening/reading/closing as we go.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"	// page_size
#include "child.h"
#include "files.h"
#include "pathnames.h"
#include "random.h"

bool read_all_files(__unused__ struct childdata *child)
{
	struct stat sb;
	char *buffer;
	unsigned int i;
	int fd;

	for (i = 0; i < files_in_index; i++) {
		int ret;
		const char *filename;

		filename = fileindex[i];

		fd = open(filename, O_RDONLY | O_NONBLOCK);
		if (fd == -1)
			continue;

		ret = (fstat(fd, &sb));
		if (ret == -1)
			goto closeout;

		if (sb.st_size == 0)
			sb.st_size = page_size;

		buffer = malloc(sb.st_size);
		if (!buffer)
			goto closeout;

		memset(buffer, 0, sb.st_size);

		ret = read(fd, buffer, sb.st_size);
//		if (ret != -1)
//			output(0, "%s:%s\n", filename, buffer);

		if (RAND_BOOL())
			sleep(1);

		free(buffer);
closeout:
		close(fd);
	}
	return TRUE;
}
