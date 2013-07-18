#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "params.h"	// logging, monochrome, quiet_level
#include "shm.h"
#include "pids.h"
#include "log.h"

FILE *mainlogfile;

void open_logfiles(void)
{
	unsigned int i;
	char *logfilename;

	logfilename = malloc(64);
	sprintf(logfilename, "trinity.log");
	unlink(logfilename);
	mainlogfile = fopen(logfilename, "a");
	if (!mainlogfile) {
		printf("## couldn't open logfile %s\n", logfilename);
		exit(EXIT_FAILURE);
	}

	for_each_pidslot(i) {
		sprintf(logfilename, "trinity-child%d.log", i);
		unlink(logfilename);
		shm->logfiles[i] = fopen(logfilename, "a");
		if (!shm->logfiles[i]) {
			printf("## couldn't open logfile %s\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
	free(logfilename);
}

void close_logfiles(void)
{
	unsigned int i;

	for_each_pidslot(i)
		if (shm->logfiles[i] != NULL)
			fclose(shm->logfiles[i]);
}

static FILE * find_logfile_handle(void)
{
	pid_t pid;
	int i;
	unsigned int j;

	pid = getpid();
	if (pid == initpid)
		return mainlogfile;

	if (pid == mainpid)
		return mainlogfile;

	if (pid == watchdog_pid)
		return mainlogfile;

	i = find_pid_slot(pid);
	if (i != PIDSLOT_NOT_FOUND)
		return shm->logfiles[i];
	else {
		/* try one more time. FIXME: This is awful. */
		sleep(1);
		i = find_pid_slot(pid);
		if (i != PIDSLOT_NOT_FOUND)
			return shm->logfiles[i];

		printf("[%d] ## Couldn't find logfile for pid %d\n", getpid(), pid);
		dump_pid_slots();
		printf("## Logfiles for pids: ");
		for_each_pidslot(j)
			printf("%p ", shm->logfiles[j]);
		printf("\n");
	}
	return NULL;
}

unsigned int highest_logfile(void)
{
	FILE *file;
	int ret;

	if (logging == FALSE)
		return 0;

	file = shm->logfiles[shm->max_children - 1];
	ret = fileno(file);

	return ret;
}

void synclogs(void)
{
	unsigned int i;
	int fd, ret;

	if (logging == FALSE)
		return;

	for_each_pidslot(i) {
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

	(void)fflush(mainlogfile);
	fsync(fileno(mainlogfile));
}

/*
 * level defines whether it gets displayed to the screen with printf.
 * (it always logs).
 *   0 = everything, even all the registers
 *   1 = Watchdog prints syscall count
 *   2 = Just the reseed values
 *
 */
void output(unsigned char level, const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;
	unsigned int len, i, j;
	char outputbuf[1024];
	char monobuf[1024];

	if (logging == FALSE && level >= quiet_level)
		return;

	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);

	if (n < 0) {
		printf("## Something went wrong in output() [%d]\n", n);
		exit(EXIT_FAILURE);
	}

	if (quiet_level > level) {
		printf("%s", outputbuf);
		(void)fflush(stdout);
	}

	if (logging == FALSE)
		return;

	handle = find_logfile_handle();
	if (!handle) {
		printf("## child logfile handle was null logging to main!\n");
		(void)fflush(stdout);
		for_each_pidslot(j)
			shm->logfiles[j] = mainlogfile;
		sleep(5);
		return;
	}

	/* If we've specified monochrome, we can just dump the buffer
	 * into the logfile as is. Otherwise, we need to strip out
	 * any ANSI codes that may be present.
	 */
	if (monochrome == TRUE) {
		fprintf(handle, "%s", outputbuf);
		(void)fflush(handle);
		return;
	}

	/* copy buffer, sans ANSI codes */
	len = strlen(outputbuf);
	for (i = 0, j = 0; i < len; i++) {
		if (outputbuf[i] == '')
			if (outputbuf[i + 2] == '1')
				i += 6;	// ANSI_COLOUR
			else
				i += 3;	// ANSI_RESET
		else {
			monobuf[j] = outputbuf[i];
			j++;
		}
	}
	monobuf[j] = '\0';

	fprintf(handle, "%s", monobuf);
	(void)fflush(handle);
}
