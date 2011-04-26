#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

static char outputbuf[1024];
char *logfilename;
FILE *logfile;

void synclog()
{
	(void)fflush(logfile);
	fsync(fileno(logfile));
}

void sync_output()
{
	(void)fflush(stdout);
	synclog();
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
		return;
	}
	printf("%s", outputbuf);

	fprintf(logfile, outputbuf);
}
