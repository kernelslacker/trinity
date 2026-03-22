#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>

#include "bdevs.h"
#include "child.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"	// progname

bool set_debug = false;
bool do_specific_syscall = false;
bool do_exclude_syscall = false;

bool do_32_arch = true;
bool do_64_arch = true;

unsigned int specific_domain = 0;
unsigned int user_specified_children = 0;

bool do_specific_domain = false;
bool no_domains[TRINITY_PF_MAX];

bool dry_run = false;
bool show_unannotated = false;
bool show_syscall_list = false;
bool show_ioctl_list = false;
unsigned char quiet_level = 1;
bool dangerous = false;
bool dropprivs = false;
bool do_syslog = false;
bool random_selection = false;
unsigned int random_selection_num;

bool clowntown = false;
bool show_stats = false;
bool group_bias = false;

bool user_set_seed = false;

unsigned char desired_group = GROUP_NONE;

char *specific_domain_optarg = NULL;

char *victim_path = NULL;

unsigned int kernel_taint_mask = 0xFFFFFFFF;
bool kernel_taint_param_occured = false;

void enable_disable_fd_usage(void)
{
	//TODO: Build this dynamically
	outputerr(" --enable-fds/--disable-fds= {sockets,pipes,perf,epoll,eventfd,pseudo,timerfd,testfile,memfd,drm}\n");
}

static void usage(void)
{
	outputerr("%s\n", progname);
	outputerr(" --arch, -a: selects syscalls for the specified architecture (32 or 64). Both by default.\n");
	outputerr(" --bdev, -b <node>:  Add /dev node to list of block devices to use for destructive tests..\n");
	outputerr(" --children,-C: specify number of child processes\n");
	outputerr(" --debug,-D: enable debug\n");
	outputerr(" --dropprivs, -X: if run as root, switch to nobody [EXPERIMENTAL]\n");
	outputerr(" --exclude,-x: don't call a specific syscall\n");
	enable_disable_fd_usage();
	outputerr(" --group,-g = {vfs,vm,net,ipc,process,signal,io_uring,bpf,sched,time}: only run syscalls from a certain group.\n");
	outputerr(" --group-bias: bias syscall selection toward the same group as the previous call.\n");
	outputerr(" --ioctls,-I: list all ioctls.\n");
	outputerr(" --kernel_taint, -T: controls which kernel taint flags should be considered, for more details refer to README file. \n");
	outputerr(" --list,-L: list all syscalls known on this architecture.\n");
	outputerr(" --domain,-P: specify specific network domain for sockets.\n");	//FIXME: P used to be 'proto' pick something better.
	outputerr(" --no_domain,-E: specify network domains to be excluded from testing.\n");
	outputerr(" --random,-r#: pick N syscalls at random and just fuzz those\n");
	outputerr(" --stats: show errno distribution per syscall before exiting\n");
	outputerr(" --syslog,-S: log important info to syslog. (useful if syslog is remote)\n");
	outputerr(" --verbose,-v: increase output verbosity. Repeat for more detail (-vv).\n");
	outputerr(" --victims,-V: path to victim files.\n");
	outputerr("\n");
	outputerr(" -c#,@: target specific syscall (takes syscall name as parameter and optionally 32 or 64 as bit-width. Default:both).\n");
	outputerr(" -N#: do # syscalls then exit.\n");
	outputerr(" -s#: use # as random seed.\n");
	exit(EXIT_SUCCESS);
}

static const char paramstr[] = "a:b:c:C:dDE:g:hILN:P:r:s:ST:V:vx:X";

static const struct option longopts[] = {
	{ "arch", required_argument, NULL, 'a' },
	{ "bdev", required_argument, NULL, 'b' },
	{ "children", required_argument, NULL, 'C' },
	{ "clowntown", no_argument, NULL, 0 },
	{ "dangerous", no_argument, NULL, 'd' },
	{ "dropprivs", no_argument, NULL, 'X'},
	{ "debug", no_argument, NULL, 'D' },
	{ "disable-fds", required_argument, NULL, 0 },
	{ "dry-run", no_argument, NULL, 0 },
	{ "enable-fds", required_argument, NULL, 0 },
	{ "exclude", required_argument, NULL, 'x' },
	{ "group", required_argument, NULL, 'g' },
	{ "group-bias", no_argument, NULL, 0 },
	{ "kernel_taint", required_argument, NULL, 'T' },
	{ "help", no_argument, NULL, 'h' },
	{ "list", no_argument, NULL, 'L' },
	{ "ioctls", no_argument, NULL, 'I' },
	{ "no_domain", required_argument, NULL, 'E' },
	{ "domain", required_argument, NULL, 'P' },
	{ "random", required_argument, NULL, 'r' },
	{ "stats", no_argument, NULL, 0 },
	{ "show-unannotated", no_argument, NULL, 0 },
	{ "syslog", no_argument, NULL, 'S' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "victims", required_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 } };

void parse_args(int argc, char *argv[])
{
	int opt;
	int opt_index = 0;

	while ((opt = getopt_long(argc, argv, paramstr, longopts, &opt_index)) != -1) {
		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				outputstd("opt:%c\n", opt);
			return;

		case 'a':
			/* One of the architectures selected*/
			do_32_arch = false;
			do_64_arch = false;
			if (strcmp(optarg, "64") == 0) {
				do_32_arch = false;
				do_64_arch = true;
			} else if (strcmp(optarg, "32") == 0) {
				do_32_arch = true;
				do_64_arch = false;
			} else {
				outputstd("can't parse %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			init_bdev_list();
			process_bdev_param(optarg);
			dump_bdev_list();
			outputstd("--bdev doesn't do anything useful yet.\n");
			exit(EXIT_SUCCESS);

		case 'c':
			/* syscalls are all disabled at this point. enable the syscall we care about. */
			do_specific_syscall = true;
			toggle_syscall(optarg, true);
			break;

		case 'C':
			user_specified_children = strtoll(optarg, NULL, 10);
			max_children = user_specified_children;

			if (max_children == 0) {
				outputerr("zero children ? WAT?\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			dangerous = true;
			break;

		case 'D':
			set_debug = true;
			break;

		case 'E':
			parse_exclude_domains(optarg);
			break;

		case 'g':
			if (!strcmp(optarg, "vm"))
				desired_group = GROUP_VM;
			else if (!strcmp(optarg, "vfs"))
				desired_group = GROUP_VFS;
			else if (!strcmp(optarg, "net"))
				desired_group = GROUP_NET;
			else if (!strcmp(optarg, "ipc"))
				desired_group = GROUP_IPC;
			else if (!strcmp(optarg, "process"))
				desired_group = GROUP_PROCESS;
			else if (!strcmp(optarg, "signal"))
				desired_group = GROUP_SIGNAL;
			else if (!strcmp(optarg, "io_uring"))
				desired_group = GROUP_IO_URING;
			else if (!strcmp(optarg, "bpf"))
				desired_group = GROUP_BPF;
			else if (!strcmp(optarg, "sched"))
				desired_group = GROUP_SCHED;
			else if (!strcmp(optarg, "time"))
				desired_group = GROUP_TIME;
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'I':
			show_ioctl_list = true;
			break;

		case 'L':
			show_syscall_list = true;
			break;

		/* Set number of syscalls to do */
		case 'N':
			syscalls_todo = strtoll(optarg, NULL, 10);
			break;

		case 'P':
			do_specific_domain = true;
			specific_domain = strtol(optarg, NULL, 10);
			specific_domain_optarg = optarg;
			break;

		case 'r':
			if (do_exclude_syscall == true) {
				outputerr("-r needs to be before any -x options.\n");
				exit(EXIT_FAILURE);
			}
			random_selection = true;
			random_selection_num = strtol(optarg, NULL, 10);
			break;

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			user_set_seed = true;
			break;


		case 'S':
			do_syslog = true;
			break;

		case 'T':
			//Load mask for kernel taint flags.
			process_taint_arg(optarg);
			if (kernel_taint_mask != 0xFFFFFFFF)
				outputstd("Custom kernel taint mask has been specified: 0x%08x (%d).\n",
					kernel_taint_mask, kernel_taint_mask);
			break;

		case 'v':
			quiet_level++;
			break;

		case 'V':
			if (victim_path == NULL) {
				victim_path = strdup(optarg);
				break;
			} else {
				outputstd("Sorry, only one victim path right now.\n");
				exit(EXIT_FAILURE);
			}
			//FIXME: Later, allow for multiple victim files
			break;

		case 'x':
			do_exclude_syscall = true;
			toggle_syscall(optarg, false);
			break;

		case 'X':
			if (getuid() == 0)
				dropprivs = true;
			else
				outputstd("Already running unprivileged, can't drop privs\n");
			break;

		case 0:
			if (strcmp("clowntown", longopts[opt_index].name) == 0)
				clowntown = true;

			if (strcmp("disable-fds", longopts[opt_index].name) == 0)
				process_fds_param(optarg, false);

			if (strcmp("dry-run", longopts[opt_index].name) == 0)
				dry_run = true;

			if (strcmp("enable-fds", longopts[opt_index].name) == 0)
				process_fds_param(optarg, true);

			if (strcmp("group-bias", longopts[opt_index].name) == 0)
				group_bias = true;

			if (strcmp("show-unannotated", longopts[opt_index].name) == 0)
				show_unannotated = true;

			if (strcmp("stats", longopts[opt_index].name) == 0)
				show_stats = true;

			break;
		}
	}
	if (quiet_level > MAX_LOGLEVEL)
		quiet_level = MAX_LOGLEVEL;

	output(1, "Done parsing arguments.\n");
}
