#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include "logfile.h"
#include "params.h"	// logging, quiet_level
#include "pids.h"
#include "shm.h"

void init_logging(void)
{
	if (logging == LOGGING_DISABLED)
		return;
	open_main_logfile();
}

void shutdown_logging(void)
{
	if (logging == LOGGING_DISABLED)
		return;
	close_logfile(&mainlogfile);
}

void init_child_logging(struct childdata *child)
{
	if (logging == LOGGING_DISABLED)
		return;
	open_child_logfile(child);
}

void shutdown_child_logging(struct childdata *child)
{
	if (logging == LOGGING_DISABLED)
		return;
	close_logfile(&child->logfile);
}
