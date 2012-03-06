#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include "trinity.h"

static struct flock logfilelock = { F_WRLCK, SEEK_SET, 0, 0, 0 };
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
	if (logging == 0)
		return;

	logfilelock.l_type = F_WRLCK;
	logfilelock.l_pid = getpid();
	if (fcntl(fileno(logfile), F_SETLKW, &logfilelock) == -1) {
		perror("fcntl F_SETLKW");
		exit(EXIT_FAILURE);
	}
}

void unlock_logfile()
{
	if (logging == 0)
		return;

	logfilelock.l_type = F_UNLCK;
	if (fcntl(fileno(logfile), F_SETLK, &logfilelock) == -1) {
		perror("fcntl F_SETLK");
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

	lock_logfile();
	fprintf(logfile, "%s", outputbuf);
	unlock_logfile();
}
