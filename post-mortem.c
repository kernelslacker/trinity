#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include "pids.h"
#include "shm.h"
#include "taint.h"
#include "trinity.h"
#include "post-mortem.h"
#include "utils.h"

static void dump_syscall_rec(FILE *fd, struct syscallrecord *rec)
{
	switch (rec->state) {
	case UNKNOWN:
		/* new child, so nothing to dump. */
		break;
	case PREP:
		/* haven't finished setting up, so don't dump. */
		break;
	case BEFORE:
		fprintf(fd, "%s\n", rec->prebuffer);
		break;
	case AFTER:
	case GOING_AWAY:
		fprintf(fd, "%s%s\n", rec->prebuffer, rec->postbuffer);
		break;
	}
}

static void dump_syscall_records(void)
{
	FILE *fd;
	unsigned int i;

	fd = fopen("trinity-post-mortem.log", "w");
	if (!fd) {
		outputerr("Failed to write post mortem log (%s)\n", strerror(errno));
		return;
	}

	for_each_child(i) {
		dump_syscall_rec(fd, &shm->children[i]->syscall);
		fprintf(fd, "\n");
	}

	fclose(fd);
}

void tainted_postmortem(void)
{
	int taint = get_taint();

	struct timespec taint_tp;

	shm->postmortem_in_progress = TRUE;

	//TODO: Sort syscall rec output by timespec, and mark when we detected taint_tp.
	clock_gettime(CLOCK_MONOTONIC, &taint_tp);

	panic(EXIT_KERNEL_TAINTED);

	output(0, "kernel became tainted! (%d/%d) Last seed was %u\n",
		taint, kernel_taint_initial, shm->seed);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Detected kernel tainting. Last seed was %u\n", shm->seed);
	closelog();

	dump_syscall_records();

	shm->postmortem_in_progress = FALSE;
}
