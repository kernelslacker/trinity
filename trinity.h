#ifndef _TRINITY_H
#define _TRINITY_H 1

#include <stdio.h>
#include <setjmp.h>
#include <sys/types.h>
#include <unistd.h>

#include "constants.h"

#define FALSE 0
#define TRUE 1

#define UNLOCKED 0
#define LOCKED 1

#ifndef S_SPLINT_S
#define __unused__ __attribute((unused))
#else
#define __unused__ /*@unused@*/
#endif

extern char *progname;
extern pid_t parentpid;

extern jmp_buf ret_jump;

void do_main_loop(void);
int child_process(void);

int find_pid_slot(pid_t mypid);
void dump_pid_slots(void);

long mkcall(int child);
void do_syscall_from_child();

void regenerate_random_page(void);

extern unsigned int seed;
void set_seed(unsigned int pidslot);

extern unsigned int fds_left_to_create;

extern unsigned int nr_sockets;
extern unsigned int specific_proto;
void open_sockets();
void find_specific_proto();

extern unsigned int fd_idx;

void open_files();
void close_files();
void open_fds(const char *dir, unsigned char add_all);
extern char *victim_path;

extern unsigned int page_size;
extern unsigned int rep;
extern long struct_fill;

/* command line args. */
void parse_args(int argc, char *argv[]);

extern unsigned char debug;
extern unsigned char do_specific_syscall;
extern unsigned char do_exclude_syscall;
extern unsigned int specific_proto;
extern unsigned char do_specific_proto;
extern char *specific_proto_optarg;
extern unsigned char dopause;
extern unsigned char show_syscall_list;
extern unsigned char quiet;
extern unsigned char monochrome;
extern unsigned char dangerous;
extern unsigned char do_syslog;
extern unsigned char logging;
extern unsigned char desired_group;
extern unsigned char user_set_seed;

extern unsigned char exit_reason;

extern unsigned char biarch;

extern char *page_zeros;
extern char *page_0xff;
extern char *page_rand;
extern char *page_allocs;

struct map {
	struct map *next;
	void *ptr;
	char *name;
};
void setup_maps();
void destroy_maps();
void * get_map();

#define ANSI_RED	"[1;31m"
#define ANSI_GREEN	"[1;32m"
#define ANSI_YELLOW	"[1;33m"
#define ANSI_BLUE	"[1;34m"
#define ANSI_MAGENTA	"[1;35m"
#define ANSI_CYAN	"[1;36m"
#define ANSI_WHITE	"[1;37m"

#define RED if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_RED);
#define GREEN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_GREEN);
#define YELLOW if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_YELLOW);
#define BLUE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_BLUE);
#define MAGENTA if (monochrome == FALSE) sptr += sprintf(sptr, "%s", ANSI_MAGENTA);
#define CYAN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_CYAN);
#define WHITE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_WHITE);

void synclogs();
void output(const char *fmt, ...);
void open_logfiles();
void close_logfiles();

extern unsigned char do_check_tainted;
int check_tainted(void);

void init_child(void);

void init_watchdog(void);
void watchdog(void);

void reap_child(pid_t childpid);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define BUG(bugtxt)	printf("%s:%s:%d %s", __FILE__, __func__, __LINE__, bugtxt);
#define UNUSED(x) (void)(x)

enum exit_reasons {
	STILL_RUNNING = 0,
	EXIT_NO_SYSCALLS_ENABLED = 1,
	EXIT_REACHED_COUNT = 2,
	EXIT_NO_FDS = 3,
	EXIT_LOST_PID_SLOT = 4,
	EXIT_PID_OUT_OF_RANGE = 5,
	EXIT_SIGINT = 6,
	EXIT_KERNEL_TAINTED = 7,
};

#endif	/* _TRINITY_H */
