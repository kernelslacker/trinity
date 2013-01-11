#ifndef _TRINITY_H
#define _TRINITY_H 1

#include <stdio.h>
#include <setjmp.h>
#include <sys/types.h>
#include <unistd.h>

#include "constants.h"

typedef enum { FALSE = 0, TRUE = 1 } bool;

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
void mask_signals_child(void);
void setup_main_signals(void);

void * alloc_shared(unsigned int size);

void do_main_loop(void);
int child_process(void);

long mkcall(int child);
void do_syscall_from_child(void);

void regenerate_random_page(void);

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(unsigned int pidslot);
void reseed(void);

extern unsigned int nr_sockets;
extern unsigned int specific_proto;
void open_sockets(void);
void find_specific_proto(const char *protoarg);

extern unsigned int page_size;
extern unsigned int rep;
extern long struct_fill;

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
extern unsigned char quiet_level;
extern bool monochrome;
extern bool dangerous;
extern bool do_syslog;
extern bool logging;
extern unsigned char desired_group;
extern bool user_set_seed;
extern char *victim_path;

extern unsigned char exit_reason;

extern bool biarch;

extern char *page_zeros;
extern char *page_0xff;
extern char *page_rand;
extern char *page_allocs;

struct map {
	struct map *next;
	void *ptr;
	char *name;
	unsigned long size;
};
void setup_maps(void);
void destroy_maps(void);
void * get_map(void);
void init_buffers(void);

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

#define MAX_LOGLEVEL 3
void synclogs(void);
void output(unsigned char level, const char *fmt, ...);
void open_logfiles(void);
void close_logfiles(void);

extern bool ignore_tainted;
int check_tainted(void);

void init_child(void);

void init_watchdog(void);

void reap_child(pid_t childpid);

extern unsigned int user_specified_children;

#define for_each_pidslot(i)	for (i = 0; i < shm->max_children; i++)

#define PIDSLOT_NOT_FOUND -1
#define EMPTY_PIDSLOT -1
int find_pid_slot(pid_t mypid);
bool pidmap_empty(void);
void dump_pid_slots(void);
int pid_is_valid(pid_t);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define BUGTXT ANSI_RED "BUG!: " ANSI_WHITE

#define BUG(bugtxt)	{ printf("%s:%s:%d %s", __FILE__, __func__, __LINE__, bugtxt); while(1); }
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
	EXIT_SHM_CORRUPTION = 8,
	EXIT_REPARENT_PROBLEM = 9,
};

#define pid_alive(_pid) kill(_pid, 0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif	/* _TRINITY_H */
