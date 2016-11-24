#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "ftrace.h"
#include "log.h"
#include "taint.h"

static int trace_fd = -1;

void setup_ftrace(void)
{
	//todo: check for root
	trace_fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
	if (trace_fd == -1) {
		if (errno != -EEXIST) {
			output(0, "Error opening tracing_on : %s\n", strerror(errno));
		}
	}
	output(0, "Opened ftrace tracing_on as fd %d\n", trace_fd);
}

void stop_ftrace_if_tainted(void)
{
	if (is_tainted() == TRUE) {
		if (trace_fd != -1) {
			if (write(trace_fd, "0", 1) == -1)
				output(0, "Stopping ftrace failed! %s\n", strerror(errno));
			close(trace_fd);
			trace_fd = -1;
		}
	}
}
