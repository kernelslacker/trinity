#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>

#include "bdevs.h"
#include "child.h"
#include "fd.h"
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
unsigned int alt_op_children = 0;

bool do_specific_domain = false;
bool no_domains[TRINITY_PF_MAX];

bool dry_run = false;
bool show_unannotated = false;
bool show_syscall_list = false;
bool show_ioctl_list = false;
unsigned char verbosity = 1;
bool dangerous = false;
bool dropprivs = false;
bool do_syslog = false;
bool random_selection = false;
unsigned int random_selection_num;

bool clowntown = false;
bool show_stats = false;
bool stats_json = false;
bool quiet = false;
bool group_bias = false;

unsigned long epoch_iterations = 0;
unsigned int epoch_timeout = 0;

/*
 * Parse a duration string with optional suffix:
 *   s = seconds (default if no suffix)
 *   m = minutes
 *   h = hours
 *   d = days
 * On success, writes the value (in seconds) to *out and returns true.
 * Returns false for empty input, garbage, multi-char suffix, unknown
 * suffix, negative values, or anything that overflows unsigned int.
 */
static bool parse_duration(const char *s, unsigned int *out)
{
	char *end;
	unsigned long val;
	unsigned long mult = 1;

	if (s == NULL || *s == '\0')
		return false;

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || errno == ERANGE)
		return false;

	if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 's': mult = 1; break;
		case 'm': mult = 60UL; break;
		case 'h': mult = 60UL * 60; break;
		case 'd': mult = 60UL * 60 * 24; break;
		default: return false;
		}
	}

	if (mult != 0 && val > ULONG_MAX / mult)
		return false;
	val *= mult;

	if (val > UINT_MAX)
		return false;

	*out = (unsigned int)val;
	return true;
}

bool no_warm_start = false;
char *warm_start_path = NULL;

bool user_set_seed = false;

unsigned char desired_group = GROUP_NONE;

char *specific_domain_optarg = NULL;

char *victim_paths[MAX_VICTIM_PATHS];
unsigned int nr_victim_paths;

unsigned int kernel_taint_mask = 0xFFFFFFFF;
bool kernel_taint_param_occured = false;

void enable_disable_fd_usage(void)
{
	dump_fd_provider_names();
}

struct option_help {
	const char *name;	/* long option name (NULL = end of table) */
	char shortopt;		/* short option char, or 0 if none */
	const char *desc;	/* help text */
};

static const struct option_help option_descs[] = {
	{ "alt-op-children",	 0,  "reserve N children to run dedicated alt ops (mmap_lifecycle, mprotect_split, ...) round-robin instead of mixing them at 1% in every child" },
	{ "arch",		'a', "selects syscalls for the specified architecture (32 or 64). Both by default." },
	{ "bdev",		'b', "Add /dev node to list of block devices to use for destructive tests." },
	{ "children",		'C', "specify number of child processes" },
	{ "clowntown",		 0,  "enable clowntown mode" },
	{ "dangerous",		'd', "enable dangerous mode" },
	{ "debug",		'D', "enable debug" },
	{ "disable-fds",	 0,  NULL },	/* handled separately */
	{ "dropprivs",		'X', "if run as root, switch to nobody [EXPERIMENTAL]" },
	{ "dry-run",		 0,  "parse args and exit without fuzzing" },
	{ "enable-fds",		 0,  NULL },	/* handled separately */
	{ "epoch-iterations",	 0,  "syscalls per epoch before restarting (0 = disabled)" },
	{ "epoch-timeout",	 0,  "seconds per epoch before restarting (0 = disabled)" },
	{ "exclude",		'x', "don't call a specific syscall" },
	{ "group",		'g', "only run syscalls from a certain group (vfs,vm,net,ipc,process,signal,io_uring,bpf,sched,time)" },
	{ "group-bias",		 0,  "bias syscall selection toward the same group as the previous call" },
	{ "help",		'h', "show this help" },
	{ "ioctls",		'I', "list all ioctls" },
	{ "kernel_taint",	'T', "controls which kernel taint flags should be considered (see README)" },
	{ "list",		'L', "list all syscalls known on this architecture" },
	{ "max-runtime",	 0,  "maximum runtime before exit, with optional suffix s/m/h/d (e.g., 30s, 10m, 2h, 1d). Overrides --epoch-timeout." },
	{ "domain",		'P', "specify specific network domain for sockets" },
	{ "quiet",		'q', "suppress the per-second progress line (other output unchanged)" },
	{ "no_domain",		'E', "specify network domains to be excluded from testing" },
	{ "random",		'r', "pick N syscalls at random and just fuzz those" },
	{ "show-unannotated",	 0,  "show unannotated syscalls" },
	{ "stats",		 0,  "show errno distribution per syscall before exiting" },
	{ "stats-json",		 0,  "emit dump_stats output as a single JSON object on stdout (machine-readable)" },
	{ "syslog",		'S', "log important info to syslog (useful if syslog is remote)" },
	{ "verbose",		'v', "increase output verbosity. Repeat for more detail (-vv)" },
	{ "victims",		'V', "path to victim files (may be repeated)" },
	{ "no-warm-start",	 0,  "skip loading and saving the persisted minicorpus" },
	{ "warm-start-path",	 0,  "override the on-disk minicorpus path (default: $XDG_CACHE_HOME/trinity/corpus/<arch>)" },
	{ NULL,			 0,  NULL },
};

/* Short-only options that don't appear in longopts. */
static const struct option_help shortonly_descs[] = {
	{ NULL, 'c', "target specific syscall (name, optionally @32 or @64)" },
	{ NULL, 'N', "do N syscalls then exit" },
	{ NULL, 's', "use N as random seed" },
	{ NULL,  0,  NULL },
};

static void usage(void)
{
	const struct option_help *h;

	outputerr("%s\n", progname);

	for (h = option_descs; h->name != NULL; h++) {
		if (h->desc == NULL)
			continue;

		if (h->shortopt)
			outputerr(" --%s, -%c: %s\n", h->name, h->shortopt, h->desc);
		else
			outputerr(" --%s: %s\n", h->name, h->desc);
	}

	enable_disable_fd_usage();

	for (h = shortonly_descs; h->shortopt != 0; h++)
		outputerr(" -%c: %s\n", h->shortopt, h->desc);

	outputerr("\n");
	exit(EXIT_SUCCESS);
}

static const char paramstr[] = "a:b:c:C:dDE:g:hILN:P:qr:s:ST:V:vx:X";

static const struct option longopts[] = {
	{ "alt-op-children", required_argument, NULL, 0 },
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
	{ "epoch-iterations", required_argument, NULL, 0 },
	{ "epoch-timeout", required_argument, NULL, 0 },
	{ "exclude", required_argument, NULL, 'x' },
	{ "group", required_argument, NULL, 'g' },
	{ "group-bias", no_argument, NULL, 0 },
	{ "kernel_taint", required_argument, NULL, 'T' },
	{ "help", no_argument, NULL, 'h' },
	{ "list", no_argument, NULL, 'L' },
	{ "max-runtime", required_argument, NULL, 0 },
	{ "ioctls", no_argument, NULL, 'I' },
	{ "no_domain", required_argument, NULL, 'E' },
	{ "domain", required_argument, NULL, 'P' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "random", required_argument, NULL, 'r' },
	{ "stats", no_argument, NULL, 0 },
	{ "stats-json", no_argument, NULL, 0 },
	{ "show-unannotated", no_argument, NULL, 0 },
	{ "syslog", no_argument, NULL, 'S' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "victims", required_argument, NULL, 'V' },
	{ "no-warm-start", no_argument, NULL, 0 },
	{ "warm-start-path", required_argument, NULL, 0 },
	{ NULL, 0, NULL, 0 } };

void parse_args(int argc, char *argv[])
{
	int opt;
	int opt_index = 0;
	bool max_runtime_set = false;
	bool epoch_timeout_set = false;

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

		case 'C': {
			char *end;
			unsigned long val;

			errno = 0;
			val = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				outputerr("can't parse '%s' as a number\n", optarg);
				exit(EXIT_FAILURE);
			}
			if (val > UINT_MAX) {
				outputerr("children value %lu exceeds UINT_MAX\n", val);
				exit(EXIT_FAILURE);
			}
			user_specified_children = (unsigned int)val;
			max_children = user_specified_children;

			if (max_children == 0) {
				outputerr("zero children ? WAT?\n");
				exit(EXIT_FAILURE);
			}
			break;
		}

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
		case 'N': {
			char *end;

			errno = 0;
			syscalls_todo = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				outputerr("can't parse '%s' as a number\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		}

		case 'P': {
			char *end;

			errno = 0;
			specific_domain = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				outputerr("can't parse '%s' as a number\n", optarg);
				exit(EXIT_FAILURE);
			}
			do_specific_domain = true;
			specific_domain_optarg = optarg;
			break;
		}

		case 'q':
			quiet = true;
			break;

		case 'r': {
			char *end;

			if (do_exclude_syscall == true) {
				outputerr("-r needs to be before any -x options.\n");
				exit(EXIT_FAILURE);
			}
			errno = 0;
			random_selection_num = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				outputerr("can't parse '%s' as a number\n", optarg);
				exit(EXIT_FAILURE);
			}
			random_selection = true;
			break;
		}

		/* Set seed */
		case 's': {
			char *end;

			errno = 0;
			seed = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				outputerr("can't parse '%s' as a number\n", optarg);
				exit(EXIT_FAILURE);
			}
			user_set_seed = true;
			break;
		}


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
			verbosity++;
			break;

		case 'V':
			if (nr_victim_paths >= MAX_VICTIM_PATHS) {
				outputerr("Too many victim paths (max %d).\n", MAX_VICTIM_PATHS);
				exit(EXIT_FAILURE);
			}
			victim_paths[nr_victim_paths] = strdup(optarg);
			if (!victim_paths[nr_victim_paths]) {
				outputerr("strdup failed\n");
				exit(EXIT_FAILURE);
			}
			nr_victim_paths++;
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
			if (strcmp("alt-op-children", longopts[opt_index].name) == 0) {
				char *end;
				unsigned long val;

				errno = 0;
				val = strtoul(optarg, &end, 10);
				if (end == optarg || *end != '\0' || errno == ERANGE) {
					outputerr("can't parse '%s' as a number\n", optarg);
					exit(EXIT_FAILURE);
				}
				if (val > UINT_MAX) {
					outputerr("--alt-op-children value %lu exceeds UINT_MAX\n", val);
					exit(EXIT_FAILURE);
				}
				alt_op_children = (unsigned int)val;
			}

			if (strcmp("clowntown", longopts[opt_index].name) == 0)
				clowntown = true;

			if (strcmp("disable-fds", longopts[opt_index].name) == 0)
				process_fds_param(optarg, false);

			if (strcmp("dry-run", longopts[opt_index].name) == 0)
				dry_run = true;

			if (strcmp("enable-fds", longopts[opt_index].name) == 0)
				process_fds_param(optarg, true);

			if (strcmp("epoch-iterations", longopts[opt_index].name) == 0)
				epoch_iterations = strtoul(optarg, NULL, 10);

			if (strcmp("epoch-timeout", longopts[opt_index].name) == 0) {
				if (max_runtime_set) {
					outputerr("warning: --max-runtime takes precedence; ignoring --epoch-timeout\n");
				} else {
					epoch_timeout = strtoul(optarg, NULL, 10);
					epoch_timeout_set = true;
				}
			}

			if (strcmp("max-runtime", longopts[opt_index].name) == 0) {
				unsigned int seconds;
				if (!parse_duration(optarg, &seconds)) {
					outputerr("can't parse '%s' as a duration (use number with optional s/m/h/d suffix)\n", optarg);
					exit(EXIT_FAILURE);
				}
				if (epoch_timeout_set)
					outputerr("warning: --max-runtime overrides previously set --epoch-timeout\n");
				epoch_timeout = seconds;
				max_runtime_set = true;
			}

			if (strcmp("group-bias", longopts[opt_index].name) == 0)
				group_bias = true;

			if (strcmp("show-unannotated", longopts[opt_index].name) == 0)
				show_unannotated = true;

			if (strcmp("stats", longopts[opt_index].name) == 0)
				show_stats = true;

			if (strcmp("stats-json", longopts[opt_index].name) == 0) {
				stats_json = true;
				show_stats = true;
			}

			if (strcmp("no-warm-start", longopts[opt_index].name) == 0)
				no_warm_start = true;

			if (strcmp("warm-start-path", longopts[opt_index].name) == 0) {
				free(warm_start_path);
				warm_start_path = strdup(optarg);
				if (!warm_start_path) {
					outputerr("strdup failed\n");
					exit(EXIT_FAILURE);
				}
			}

			break;
		}
	}
	if (verbosity > MAX_LOGLEVEL)
		verbosity = MAX_LOGLEVEL;

	output(1, "Done parsing arguments.\n");
}
