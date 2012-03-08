#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include "trinity.h"

static char outputbuf[1024];
char *logfilename;
FILE *logfile;

void synclog()
{
	if (logging == 0)
		return;

	(void)fflush(logfile);
	fsync(fileno(logfile));
}

void sync_output()
{
	(void)fflush(stdout);
	synclog();
}

void lock_logfile()
{
	struct flock logfilelock;

	if (logging == 0)
		return;

	logfilelock.l_type = F_WRLCK;
	logfilelock.l_whence = SEEK_SET;
	logfilelock.l_start = 0;
	logfilelock.l_len = 0;
	logfilelock.l_pid = getpid();
	if (fcntl(fileno(logfile), F_SETLKW, &logfilelock) == -1) {
		printf("[%d] ", getpid());
		perror("fcntl lock F_SETLKW");
		exit(EXIT_FAILURE);
	}
}

void unlock_logfile()
{
	struct flock logfilelock;

	if (logging == 0)
		return;

	logfilelock.l_type = F_UNLCK;
	logfilelock.l_whence = SEEK_SET;
	logfilelock.l_start = 0;
	logfilelock.l_len = 0;
	logfilelock.l_pid = getpid();
	if (fcntl(fileno(logfile), F_SETLKW, &logfilelock) == -1) {
		printf("[%d] ", getpid());
		perror("fcntl unlock F_SETLKW\n");
		exit(EXIT_FAILURE);
	}
}

void output(const char *fmt, ...)
{
	va_list args;
	int n;

	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);

	if (n < 0) {
		printf("Something went wrong in output() [%d]\n", n);
		exit(EXIT_FAILURE);
	}

	if (!quiet)
		printf("%s", outputbuf);

	if (logging == 0)
		return;

	if (logfile == NULL) {
		perror("Logfile not open!\n");
		exit(EXIT_FAILURE);
	}
	fprintf(logfile, "%s", outputbuf);
}
