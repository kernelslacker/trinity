#ifndef _PARAMS_H
#define _PARAMS_H 1

#include "types.h"

/* command line args. */
void parse_args(int argc, char *argv[]);

extern bool debug;
extern bool do_specific_syscall;
extern bool do_exclude_syscall;
extern unsigned int specific_proto;
extern bool do_specific_proto;
extern char *specific_proto_optarg;
extern bool dopause;
extern bool show_syscall_list;
extern bool show_ioctl_list;
extern unsigned char quiet_level;
extern bool verbose;
extern bool monochrome;
extern bool dangerous;
extern bool do_syslog;
extern bool logging;
extern unsigned char desired_group;
extern bool user_set_seed;
extern char *victim_path;
extern bool no_files;
extern bool random_selection;
extern unsigned int random_selection_num;

#endif	/* _PARAMS_H */
