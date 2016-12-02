#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "ftrace.h"
#include "log.h"

static int trace_fd = -1;

void setup_ftrace(void)
{
	//todo: check for root
	trace_fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
	if (trace_fd == -1) {
		if (errno != -EEXIST) {
			output(0, "Error opening tracing_on : %s\n", strerror(errno));
			return;
		}
	}
	output(0, "Opened ftrace tracing_on as fd %d\n", trace_fd);
}

void stop_ftrace(void)
{
	if (trace_fd != -1) {
		if (write(trace_fd, "0", 1) == -1)
			output(0, "Stopping ftrace failed! %s\n", strerror(errno));
	} else {
		output(0, "trace_fd was %d\n", trace_fd);
	}
}
