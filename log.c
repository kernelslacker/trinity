#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "trinity.h"
#include "shm.h"

FILE *parentlogfile;

void open_logfiles()
{
	unsigned int i;
	char *logfilename;

	logfilename = malloc(64);
	sprintf(logfilename, "trinity-%d.log", shm->parentpid);
	unlink(logfilename);
	parentlogfile = fopen(logfilename, "a");
	if (!parentlogfile) {
		printf("## couldn't open logfile %s\n", logfilename);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < shm->nr_childs; i++) {
		logfilename = malloc(64);
		sprintf(logfilename, "trinity-%d-child%d.log", shm->parentpid, i);
		unlink(logfilename);
		shm->logfiles[i] = fopen(logfilename, "a");
		if (!shm->logfiles[i]) {
			printf("## couldn't open logfile %s\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
	free(logfilename);
}

void close_logfiles()
{
	unsigned int i;

	for (i = 0; i < shm->nr_childs; i++)
		if (shm->logfiles[i] != NULL)
			fclose(shm->logfiles[i]);
}

static FILE * find_logfile_handle()
{
	pid_t pid;
	int i;
	unsigned int j;

	pid = getpid();
	if (pid == shm->parentpid)
		return parentlogfile;

	if (pid == shm->watchdog_pid)
		return parentlogfile;

	i = find_pid_slot(pid);
	if (i != -1)
		return shm->logfiles[i];
	else {
		printf("[%d] ## Couldn't find logfile for pid %d\n", getpid(), pid);
		dump_pid_slots();
		printf("## Logfiles for pids: ");
		for (j = 0; j < shm->nr_childs; j++)
			printf("%p ", shm->logfiles[j]);
		printf("\n");
	}
	return NULL;
}

void synclogs()
{
	unsigned int i;
	int fd, ret;

	if (logging == FALSE)
		return;

	for (i = 0; i < shm->nr_childs; i++) {
		ret = fflush(shm->logfiles[i]);
		if (ret == EOF) {
			printf("## logfile flushing failed! %s\n", strerror(errno));
			continue;
		}

		fd = fileno(shm->logfiles[i]);
		if (fd != -1) {
			ret = fsync(fd);
			if (ret != 0)
				printf("## fsyncing logfile %d failed. %s\n", i, strerror(errno));
		}
	}

	(void)fflush(parentlogfile);
	fsync(fileno(parentlogfile));
}

void output(const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;
	unsigned int len, i, j;
	char outputbuf[1024];
	char monobuf[1024];

	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);

	if (n < 0) {
		printf("## Something went wrong in output() [%d]\n", n);
		exit(EXIT_FAILURE);
	}

	if (!quiet)
		printf("%s", outputbuf);

	if (logging == FALSE)
		return;

	handle = find_logfile_handle();
	if (!handle) {
		printf("## child logfile handle was null logging to main!\n");
		handle = parentlogfile;
		sleep(5);
		return;
	}

	if (monochrome == TRUE) {
		fprintf(handle, "%s", outputbuf);
		return;
	}

	len = strlen(outputbuf);
	for (i = 0, j = 0; i < len; i++) {
		if (outputbuf[i] == '')
			i += 6;
		else {
			monobuf[j] = outputbuf[i];
			j++;
		}
	}
	monobuf[j] = '\0';

	fprintf(handle, "%s", monobuf);
	(void)fflush(handle);
}
