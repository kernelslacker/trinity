#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include "log.h"
#include "pids.h"
#include "shm.h"
#include "taint.h"
#include "post-mortem.h"

#if 0
static void dump_syscall_rec(int childno, int fd, struct syscallrecord *rec)
{
	switch (rec->state) {
	case UNKNOWN:
		/* new child, so nothing to dump. */
		break;
	case PREP:
		/* haven't finished setting up, so don't dump. */
		break;
	case BEFORE:
		output_syscall_prefix_to_fd(childno, fd, TRUE);
		break;
	case AFTER:
		output_syscall_prefix_to_fd(childno, fd, TRUE);
		err = IS_ERR(rec->retval);
		if (err)
			output_syscall_postfix_err(rec->retval, rec->errno_post, fd, TRUE);
		else
			output_syscall_postfix_success(rec->retval, fd, TRUE);
		break;
	case GOING_AWAY:
		output_syscall_prefix_to_fd(childno, fd, TRUE);
		break;
	}
}

static void dump_syscall_records(void)
{
	int fd;
	unsigned int i;

	fd = open("trinity-post-mortem.log", O_WRONLY);
	if (fd < 0) {
		outputerr("Failed to write post mortem log (%s)\n", strerrror(errno));
		return;
	}

	for_each_child(i) {
		dump_syscall_rec(i, fd, &shm->previous[childno]);
		dump_syscall_rec(i, fd, &shm->syscall[childno]);
	}

	close(fd);
}
#endif

void tainted_postmortem(int taint)
{
	shm->exit_reason = EXIT_KERNEL_TAINTED;

	gettimeofday(&shm->taint_tv, NULL);

	output(0, "kernel became tainted! (%d/%d) Last seed was %u\n",
		taint, kernel_taint_initial, shm->seed);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Detected kernel tainting. Last seed was %u\n", shm->seed);
	closelog();
}
