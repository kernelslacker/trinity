#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "syscall.h"
#include "trinity.h"

bool debug = FALSE;

bool do_specific_syscall = FALSE;
bool do_exclude_syscall = FALSE;

unsigned int specific_proto = 0;
unsigned int user_specified_children = 0;

bool do_specific_proto = FALSE;

bool dopause = FALSE;
bool show_syscall_list = FALSE;
unsigned char quiet_level = 0;
bool monochrome = FALSE;
bool dangerous = FALSE;
bool logging = TRUE;
bool do_syslog = FALSE;

bool user_set_seed = FALSE;

unsigned char desired_group = GROUP_NONE;

char *specific_proto_optarg;

char *victim_path;

static int parse_victim_path(char *opt)
{
	struct stat statbuf;
	int status;

	status = stat(opt, &statbuf);
	if (status == -1) {
		printf("stat failed\n");
		return -1;
	}

	if (!(S_ISDIR(statbuf.st_mode))) {
		printf("Victim path not a directory\n");
		return -1;
	}

	victim_path = strdup(opt);

	return 0;
}


static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, " --children,-C: specify number of child processes\n");
	fprintf(stderr, " --exclude,-x: don't call a specific syscall\n");
	fprintf(stderr, " --group,-g: only run syscalls from a certain group (So far just 'vm').\n");
	fprintf(stderr, " --list,-L: list all syscalls known on this architecture.\n");
	fprintf(stderr, " --logging,-l: (off=disable logging).\n");
	fprintf(stderr, " --monochrome,-m: don't output ANSI codes\n");
	fprintf(stderr, " --proto,-P: specify specific network protocol for sockets.\n");
	fprintf(stderr, " --quiet,-q: less output.\n");
	fprintf(stderr, " --syslog,-S: log important info to syslog. (useful if syslog is remote)\n");
	fprintf(stderr, " --victims,-V: path to victim files.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " -c#: target specific syscall (takes syscall name as parameter).\n");
	fprintf(stderr, " -N#: do # syscalls then exit.\n");
	fprintf(stderr, " -p:  pause after syscall.\n");
	fprintf(stderr, " -s#: use # as random seed.\n");
	exit(EXIT_SUCCESS);
}

void parse_args(int argc, char *argv[])
{
	int opt;

	struct option longopts[] = {
		{ "children", required_argument, NULL, 'C' },
		{ "dangerous", no_argument, NULL, 'd' },
		{ "debug", no_argument, NULL, 'D' },
		{ "exclude", required_argument, NULL, 'x' },
		{ "group", required_argument, NULL, 'g' },
		{ "help", no_argument, NULL, 'h' },
		{ "list", no_argument, NULL, 'L' },
		{ "logging", required_argument, NULL, 'l' },
		{ "monochrome", no_argument, NULL, 'm' },
		{ "proto", required_argument, NULL, 'P' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "syslog", no_argument, NULL, 'S' },
		{ "victims", required_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "c:C:dDg:hl:LN:mP:pqs:SV:x:", longopts, NULL)) != -1) {
		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				printf("opt:%c\n", opt);
			return;

		case '\0':
			return;

		case 'c':
			/* syscalls are all disabled at this point. enable the syscall we care about. */
			do_specific_syscall = TRUE;
			toggle_syscall(optarg, TRUE);
			printf("Enabling syscall %s\n", optarg);
			break;

		case 'C':
			user_specified_children = strtoll(optarg, NULL, 10);
			break;

		case 'd':
			dangerous = 1;
			break;

		case 'D':
			debug = 1;
			break;

		case 'g':
			if (!strcmp(optarg, "vm"))
				desired_group = GROUP_VM;
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'l':
			if (!strcmp(optarg, "off"))
				logging = 0;
			break;

		case 'L':
			show_syscall_list = TRUE;
			break;

		case 'm':
			monochrome = TRUE;
			break;

		/* Set number of syscalls to do */
		case 'N':
			syscalls_todo = strtoll(optarg, NULL, 10) + 1;
			break;

		/* Pause after each syscall */
		case 'p':
			dopause = 1;
			break;

		case 'P':
			do_specific_proto = 1;
			specific_proto = strtol(optarg, NULL, 10);
			specific_proto_optarg = optarg;
			break;

		case 'q':
			quiet_level++;
			break;

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			user_set_seed = TRUE;
			break;


		case 'S':
			do_syslog = TRUE;
			break;

		case 'V':
			if (parse_victim_path(optarg) < 0) {
				printf("oops\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'x':
			/* First time we see a '-x', set all syscalls to enabled, then selectively disable. */
			if (do_exclude_syscall == FALSE)
				mark_all_syscalls_active();

			do_exclude_syscall = TRUE;
			toggle_syscall(optarg, FALSE);
			break;
		}
	}
	if (quiet_level > MAX_LOGLEVEL)
		quiet_level = MAX_LOGLEVEL;

	quiet_level = MAX_LOGLEVEL - quiet_level;
}
