#ifndef _TRINITY_H
#define _TRINITY_H 1

#include <stdio.h>
#include <setjmp.h>
#include <sys/types.h>
#include <unistd.h>

#include "constants.h"

#define FALSE 0
#define TRUE 1

#ifndef S_SPLINT_S
#define __unused__ __attribute((unused))
#else
#define __unused__ /*@unused@*/
#endif

extern pid_t parentpid;

extern unsigned char debug;

extern jmp_buf ret_jump;

void syscall_list(void);
void main_loop(void);
int child_process(void);

int find_pid_slot(pid_t mypid);

long mkcall(unsigned int call);
void do_syscall_from_child();

void regenerate_random_page(void);

void seed_from_tod();

extern unsigned int fds_left_to_create;

extern unsigned int socks;
extern unsigned int specific_proto;
void open_sockets();

extern unsigned int fd_idx;

void open_files();
void close_files();
void open_fds(const char *dir);

extern unsigned int page_size;
extern unsigned int rep;
extern unsigned char do_specific_proto;
extern unsigned char do_specific_syscall;
extern unsigned long specific_syscall;
extern unsigned char dopause;
extern long struct_fill;
extern unsigned char logging;
extern unsigned char extrafork;

extern unsigned char biarch;

extern unsigned long syscalls_per_child;

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

#define RED	"[1;31m"
#define GREEN	"[1;32m"
#define YELLOW	"[1;33m"
#define BLUE	"[1;34m"
#define MAGENTA	"[1;35m"
#define CYAN	"[1;36m"
#define WHITE	"[1;37m"

extern unsigned char quiet;
void synclogs();
void output(const char *fmt, ...);
void open_logfiles();
void close_logfiles();

extern unsigned char do_check_tainted;
int check_tainted(void);

void init_child(void);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#endif	/* _TRINITY_H */
