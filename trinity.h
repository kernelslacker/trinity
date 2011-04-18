#ifndef _TRINITY_H
#define _TRINITY_H 1

#include <stdio.h>
#include <setjmp.h>

#ifndef S_SPLINT_S
#define __unused__ __attribute((unused))
#else
#define __unused__ /*@unused@*/
#endif

extern jmp_buf ret_jump;

void syscall_list(void);
void check_sanity(void);
void mask_signals(void);
void do_main_loop(void);
void display_opmode(void);
void regenerate_random_page(void);

struct arglist {
	unsigned int num;
	unsigned int values[1024];
};

struct syscalltable {
	char name[80];
	unsigned int num_args;
	void (*sanitise)(
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *);
	unsigned int flags;

	unsigned int arg1type;
	unsigned int arg2type;
	unsigned int arg3type;
	unsigned int arg4type;
	unsigned int arg5type;
	unsigned int arg6type;

	char *arg1name;
	char *arg2name;
	char *arg3name;
	char *arg4name;
	char *arg5name;
	char *arg6name;

	unsigned int low1range, hi1range;
	unsigned int low2range, hi2range;
	unsigned int low3range, hi3range;
	unsigned int low4range, hi4range;
	unsigned int low5range, hi5range;
	unsigned int low6range, hi6range;

	struct arglist arg1list;
	struct arglist arg2list;
	struct arglist arg3list;
	struct arglist arg4list;
	struct arglist arg5list;
	struct arglist arg6list;
};

extern struct syscalltable *syscalls;

extern unsigned int page_size;
extern unsigned long long syscallcount;
extern unsigned int opmode;
extern char *opmodename[];
extern char *structmodename[];
extern int do_32bit;
extern unsigned int max_nr_syscalls;
extern unsigned char intelligence;
extern unsigned int structmode;
extern unsigned long regval;
extern unsigned char rotate_mask;
extern unsigned int rep;
extern unsigned char do_specific_syscall;
extern unsigned long specific_syscall;
extern unsigned char dopause;
extern long struct_fill;
extern unsigned char bruteforce;
extern unsigned char nofork;
extern char passed_type;

struct shm_s {
	unsigned long execcount;
	unsigned long successes;
	unsigned long failures;
	unsigned long retries;
};
extern struct shm_s *shm;

extern unsigned char ctrlc_hit;

extern char *userbuffer;
extern char *page_zeros;
extern char *page_0xff;
extern char *page_rand;

struct map {
	struct map *next;
	void *ptr;
};
void setup_maps();
void * get_map();

#define RED	"[1;31m"
#define GREEN	"[1;32m"
#define YELLOW	"[1;33m"
#define BLUE	"[1;34m"
#define MAGENTA	"[1;35m"
#define CYAN	"[1;36m"
#define WHITE	"[1;37m"

extern char *logfilename;
extern FILE *logfile;

#define synclog() do {      \
	fflush(logfile); \
	fsync(fileno(logfile)); \
} while (0)

#define writelog(...) do {      \
	fprintf(logfile, ## __VA_ARGS__); \
	synclog(); \
} while (0)

#define writelog_nosync(...) do {      \
	fprintf(logfile, ## __VA_ARGS__); \
} while (0)

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ROTATE 2

#define TYPE_UNDEFINED 0
#define TYPE_VALUE 1
#define TYPE_STRUCT 2

#define STRUCT_UNDEFINED 0
#define STRUCT_CONST 1
#define STRUCT_RAND 2


#endif	/* _TRINITY_H */
