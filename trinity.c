#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "fd.h"
#include "files.h"
#include "ioctls.h"
#include "maps.h"
#include "objects.h"
#include "pids.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "signals.h"
#include "shm.h"
#include "sysv-shm.h"
#include "futex.h"
#include "stats.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
#include "version.h"

pid_t mainpid;

char *progname = NULL;

unsigned int page_size;
unsigned int num_online_cpus;
bool no_bind_to_cpu;
unsigned int max_children;
struct rlimit max_files_rlimit;

struct obj_init_entry {
	const char *name;
	void (*init)(void);
};

static const struct obj_init_entry object_init_table[] = {
	{ "futexes",	create_futexes },
	{ "sysv_shms",	create_sysv_shms },
};

static void init_global_objects(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(object_init_table); i++) {
		output(0, "Initializing %s objects.\n", object_init_table[i].name);
		object_init_table[i].init();
	}
}

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
	const char taskname[13]="trinity-main";

	outputstd("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");

	setlinebuf(stdout);

	progname = argv[0];

	mainpid = getpid();

    if (getrlimit(RLIMIT_NOFILE, &max_files_rlimit) != 0) {
		max_files_rlimit.rlim_cur = 1024;
		max_files_rlimit.rlim_max = 1024;
	}

	page_size = getpagesize();
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	num_online_cpus = (ncpus > 0) ? (unsigned int)ncpus : 1;
	max_children = num_online_cpus * 4;	/* possibly overridden in params. */

	select_syscall_tables();

	create_shm();

	parse_args(argc, argv);

	init_uids();

	change_tmp_dir();

	init_shm();

	init_taint_checking();

	if (munge_tables() == false) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (show_syscall_list == true) {
		dump_syscall_tables();
		goto out;
	}

	if (show_ioctl_list == true) {
		dump_ioctls();
		goto out;
	}

	if (show_unannotated == true) {
		show_unannotated_args();
		goto out;
	}

	init_syscalls();

	do_uid0_check();

	if (do_specific_domain == true)
		find_specific_domain(specific_domain_optarg);

	pids_init();

	fd_hash_init();
	init_object_lists(OBJ_GLOBAL, NULL);

	setup_initial_mappings();

	parse_devices();

	init_global_objects();

	setup_main_signals();

	no_bind_to_cpu = RAND_BOOL();

	prctl(PR_SET_NAME, (unsigned long) &taskname);

	if (open_fds() == false) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			panic(EXIT_FD_INIT_FAILURE);

		_exit(EXIT_FAILURE);
	}

	main_loop();

	destroy_global_objects();

	output(0, "Ran %ld syscalls. Successes: %ld  Failures: %ld\n",
		shm->stats.op_count, shm->stats.successes, shm->stats.failures);
	if (show_stats == true)
		dump_stats();

	ret = set_exit_code(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED));
out:

	exit(ret);
}
