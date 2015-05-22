#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"
#include "config.h"	// for VERSION
#include "fd.h"
#include "files.h"
#include "ioctls.h"
#include "log.h"
#include "maps.h"
#include "pids.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "signals.h"
#include "shm.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
#include "version.h"

char *progname = NULL;

unsigned int page_size;
unsigned int num_online_cpus;
unsigned int max_children;

/*
 * just in case we're not using the test.sh harness, we
 * change to the tmp dir if it exists.
 */
static void change_tmp_dir(void)
{
	struct stat sb;
	const char tmpdir[]="tmp/";
	int ret;

	/* Check if it exists, bail early if it doesn't */
	ret = (lstat(tmpdir, &sb));
	if (ret == -1)
		return;

	/* Just in case a previous run screwed the perms. */
	ret = chmod(tmpdir, 0777);
	if (ret == -1)
		output(0, "Couldn't chmod %s to 0777.\n", tmpdir);

	ret = chdir(tmpdir);
	if (ret == -1)
		output(0, "Couldn't change to %s\n", tmpdir);
}

static int set_exit_code(enum exit_reasons reason)
{
	int ret = EXIT_SUCCESS;

	switch (reason) {
	case EXIT_NO_SYSCALLS_ENABLED:
	case EXIT_NO_FDS:
	case EXIT_LOST_CHILD:
	case EXIT_PID_OUT_OF_RANGE:
	case EXIT_KERNEL_TAINTED:
	case EXIT_SHM_CORRUPTION:
	case EXIT_REPARENT_PROBLEM:
	case EXIT_NO_FILES:
	case EXIT_MAIN_DISAPPEARED:
	case EXIT_UID_CHANGED:
	case EXIT_LOCKING_CATASTROPHE:
	case EXIT_FORK_FAILURE:
	case EXIT_FD_INIT_FAILURE:
	case EXIT_LOGFILE_OPEN_ERROR:
		ret = EXIT_FAILURE;
		break;

	default:
	/* the next are just to shut up -Werror=switch-enum
	 * pragma's are just as ugly imo. */
	case STILL_RUNNING:
	case EXIT_REACHED_COUNT:
	case EXIT_SIGINT:
	case NUM_EXIT_REASONS:
		break;
	}
	return ret;
}

int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;
	int childstatus;
	pid_t pid;
	const char taskname[13]="trinity-main";

	outputstd("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");

	progname = argv[0];

	initpid = getpid();

	page_size = getpagesize();
	num_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	max_children = num_online_cpus;	/* possibly overridden in params. */

	set_seed(0);

	select_syscall_tables();

	create_shm();

	/* We do this before the parse_args because --fds will need to
	 * operate on it when implemented.
	 */
	setup_fd_providers();

	parse_args(argc, argv);

	init_uids();

	change_tmp_dir();

	if (logging == TRUE)
		open_main_logfile();

	init_shm();

	kernel_taint_initial = check_tainted();
	if (kernel_taint_initial != 0)
		output(0, "Kernel was tainted on startup. Will ignore flags that are already set.\n");

	if (munge_tables() == FALSE) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (show_syscall_list == TRUE) {
		dump_syscall_tables();
		goto out;
	}

	init_syscalls();

	if (show_ioctl_list == TRUE) {
		dump_ioctls();
		goto out;
	}

	do_uid0_check();

	if (do_specific_domain == TRUE)
		find_specific_domain(specific_domain_optarg);

	setup_initial_mappings();

	parse_devices();

	pids_init();

	setup_main_signals();

	/* check if we ctrl'c or something went wrong during init. */
	if (shm->exit_reason != STILL_RUNNING)
		goto cleanup_fds;

	init_watchdog();

	/* do an extra fork so that the watchdog and the children don't share a common parent */
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		shm->mainpid = getpid();

		setup_main_signals();

		output(0, "Main thread is alive.\n");
		prctl(PR_SET_NAME, (unsigned long) &taskname);
		set_seed(0);

		if (open_fds() == FALSE) {
			if (shm->exit_reason != STILL_RUNNING)
				panic(EXIT_FD_INIT_FAILURE);	// FIXME: Later, push this down to multiple EXIT's.

			exit_main_fail();
		}

		if (dropprivs == TRUE)	//FIXME: Push down into child processes later.
			drop_privs();

		main_loop();

		shm->mainpid = 0;
		_exit(EXIT_SUCCESS);
	}

	/* wait for main loop process to exit. */
	(void)waitpid(pid, &childstatus, 0);

	/* wait for watchdog to exit. */
	waitpid(watchdog_pid, &childstatus, 0);

	output(0, "Ran %ld syscalls. Successes: %ld  Failures: %ld\n",
		shm->stats.total_syscalls_done - 1, shm->stats.successes, shm->stats.failures);

cleanup_fds:

	close_sockets();

	destroy_initial_mappings();

	if (logging == TRUE)
		close_logfile(&mainlogfile);

	ret = set_exit_code(shm->exit_reason);
out:

	exit(ret);
}
