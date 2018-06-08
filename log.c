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
#include "udp.h"

void init_logging(void)
{
	switch (logging) {
	case LOGGING_DISABLED:
		return;
	case LOGGING_FILES:
		open_main_logfile();
		return;
	case LOGGING_UDP:
		init_udp_logging(logging_args);
		return;
	}
}

void shutdown_logging(void)
{
	switch (logging) {
	case LOGGING_DISABLED:
		return;
	case LOGGING_FILES:
		close_logfile(&mainlogfile);
		return;
	case LOGGING_UDP:
		return;
	}
}

void init_child_logging(struct childdata *child)
{
	switch (logging) {
	case LOGGING_DISABLED:
		return;
	case LOGGING_FILES:
		open_child_logfile(child);
		return;
	case LOGGING_UDP:
		shutdown_udp_logging();
		return;
	}
}

void shutdown_child_logging(struct childdata *child)
{
	switch (logging) {
	case LOGGING_DISABLED:
		return;
	case LOGGING_FILES:
		close_logfile(&child->logfile);
		return;
	case LOGGING_UDP:
		return;
	}
}
