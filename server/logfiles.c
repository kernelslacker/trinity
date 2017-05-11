#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "logfiles.h"
#include "utils.h"

int open_logfile(const char *logfilename)
{
	int fd;

	fd = open(logfilename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (!fd)
		printf("## couldn't open logfile %s\n", logfilename);

	return fd;
}

int open_child_logfile(unsigned int num)
{
	char *logfilename;
	int fd;

	logfilename = zmalloc(64);
	sprintf(logfilename, "trinity-child%u.log", num);

	fd = open_logfile(logfilename);
	if (!fd)
		exit(EXIT_FAILURE);

	free(logfilename);
	return fd;
}
