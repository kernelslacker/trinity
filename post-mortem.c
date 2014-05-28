#include <syslog.h>
#include <sys/time.h>
#include "log.h"
#include "shm.h"
#include "taint.h"
#include "post-mortem.h"

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
