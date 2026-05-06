#pragma once

#include "types.h"

/* glibc headers might be older than the kernel, define our own PF_MAX */
#define TRINITY_PF_MAX 46
#define TAINT_PROPRIETARY_MODULE        0
#define TAINT_FORCED_MODULE             1
#define TAINT_UNSAFE_SMP                2
#define TAINT_FORCED_RMMOD              3
#define TAINT_MACHINE_CHECK             4
#define TAINT_BAD_PAGE                  5
#define TAINT_USER                      6
#define TAINT_DIE                       7
#define TAINT_OVERRIDDEN_ACPI_TABLE     8
#define TAINT_WARN                      9
#define TAINT_CRAP                      10
#define TAINT_FIRMWARE_WORKAROUND       11
#define TAINT_OOT_MODULE                12

/* command line args. */
void parse_args(int argc, char *argv[]);

/*
 * Apply the derived max_children cap to the default num_online_cpus*4
 * value when -C was not used.  No-op when -C is in effect: the parser
 * already validated user_specified_children against the same cap.
 */
void clamp_default_max_children(void);

extern bool set_debug;

extern bool do_32_arch;
extern bool do_64_arch;

extern bool do_specific_syscall;
extern bool do_exclude_syscall;
extern unsigned int specific_domain;
extern bool do_specific_domain;
extern char *specific_domain_optarg;
extern bool no_domains[TRINITY_PF_MAX];
extern bool dry_run;
extern bool show_unannotated;
extern bool show_syscall_list;
extern bool show_ioctl_list;
extern bool show_disabled_syscalls;
extern unsigned char verbosity;
extern bool dangerous;
extern bool dropprivs;
extern bool do_syslog;
extern unsigned char desired_group;
extern bool group_bias;
extern bool user_set_seed;
extern char *victim_paths[];
extern unsigned int nr_victim_paths;
#define MAX_VICTIM_PATHS 32
extern bool random_selection;
extern unsigned int random_selection_num;

extern bool clowntown;
extern bool show_stats;
extern bool stats_json;
extern bool quiet;

extern unsigned int kernel_taint_mask;
extern bool kernel_taint_param_occured;

extern unsigned int user_specified_children;
extern unsigned int alt_op_children;

/*
 * Hybrid bandit/explorer split: when --strategy=bandit is in effect, the
 * first `explorer_children` child slots ignore the bandit's pick and run
 * STRATEGY_RANDOM unconditionally as an always-on uniform baseline.  Their
 * coverage discoveries are recorded separately and excluded from the
 * bandit's reward signal so the explorer pool acts as an independent
 * canary rather than biasing arm selection.
 *
 * Default (when --explorer-children is not passed) is computed as
 * max_children/8 by clamp_default_explorer_children() after parse_args
 * has finalised max_children.  user_specified_explorer_children records
 * whether the operator passed the flag explicitly so the default-fill
 * path can leave their value alone.
 */
extern unsigned int explorer_children;
extern bool user_specified_explorer_children;
void clamp_default_explorer_children(void);

extern unsigned long epoch_iterations;
extern unsigned int epoch_timeout;

extern bool no_warm_start;
extern char *warm_start_path;

extern bool do_effector_map;

void enable_disable_fd_usage(void);
