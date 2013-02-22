#ifndef _TRINITY_SYSCALL_H
#define _TRINITY_SYSCALL_H 1

#include "trinity.h"

enum argtype {
	ARG_UNDEFINED = 0,
	ARG_RANDOM_INT = 1,
	ARG_FD = 2,
	ARG_LEN = 3,
	ARG_ADDRESS = 4,
	//ARG_UNUSED = 5,			//RE-USE
	ARG_NON_NULL_ADDRESS = 6,
	ARG_PID = 7,
	ARG_RANGE = 8,
	ARG_OP = 9,
	ARG_LIST = 10,
	ARG_RANDPAGE = 11,
	ARG_CPU = 12,
	ARG_PATHNAME = 13,
	ARG_IOVEC = 14,
	ARG_IOVECLEN = 15,
	ARG_SOCKADDR = 16,
	ARG_SOCKADDRLEN = 17,
};

struct arglist {
	unsigned int num;
	unsigned int values[32];
};

struct syscall {
	void (*sanitise)(int childno);
	void (*post)(int);

	unsigned int number;
	const char name[80];
	const unsigned int num_args;
	unsigned int flags;

	const enum argtype arg1type;
	const enum argtype arg2type;
	const enum argtype arg3type;
	const enum argtype arg4type;
	const enum argtype arg5type;
	const enum argtype arg6type;

	const char *arg1name;
	const char *arg2name;
	const char *arg3name;
	const char *arg4name;
	const char *arg5name;
	const char *arg6name;

	/* FIXME: At some point, if we grow more type specific parts here,
	 * it may be worth union-ising this
	 */

	/* ARG_RANGE */
	const unsigned int low1range, hi1range;
	const unsigned int low2range, hi2range;
	const unsigned int low3range, hi3range;
	const unsigned int low4range, hi4range;
	const unsigned int low5range, hi5range;
	const unsigned int low6range, hi6range;

	/* ARG_OP / ARG_LIST */
	const struct arglist arg1list;
	const struct arglist arg2list;
	const struct arglist arg3list;
	const struct arglist arg4list;
	const struct arglist arg5list;
	const struct arglist arg6list;

	const unsigned int group;
	const int rettype;
};

#define RET_BORING		-1
#define RET_NONE		0
#define RET_ZERO_SUCCESS	1
#define RET_FD			2
#define RET_KEY_SERIAL_T	3
#define RET_PID_T		4
#define RET_PATH		5
#define RET_NUM_BYTES		6
#define RET_GID_T		7
#define RET_UID_T		8

#define GROUP_NONE	0
#define GROUP_VM	1

struct syscalltable {
	struct syscall *entry;
};
extern const struct syscalltable *syscalls;
extern const struct syscalltable *syscalls_32bit;
extern const struct syscalltable *syscalls_64bit;

extern unsigned long syscalls_todo;
extern unsigned int max_nr_syscalls;
extern unsigned int max_nr_32bit_syscalls;
extern unsigned int max_nr_64bit_syscalls;

extern bool use_32bit;
extern bool use_64bit;

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)
#define BORING (1<<3)
#define ACTIVE (1<<4)
#define NEED_ALARM (1<<5)

void setup_syscall_tables(void);
int search_syscall_table(const struct syscalltable *table, unsigned int nr_syscalls, const char *arg);
int validate_specific_syscall(const struct syscalltable *table, int call);
void mark_all_syscalls_active(void);
void toggle_syscall(char *arg, unsigned char state);
void dump_syscall_tables(void);
int setup_syscall_group(unsigned int desired_group);
int validate_syscall_tables(void);
bool no_syscalls_enabled(void);
int validate_syscall_table_64(void);
int validate_syscall_table_32(void);
void sanity_check_tables(void);
const char * print_syscall_name(unsigned int callno, bool bitsize);

#define for_each_32bit_syscall(i) \
	for (i = 0; i < max_nr_32bit_syscalls; i++)
#define for_each_64bit_syscall(i) \
	for (i = 0; i < max_nr_64bit_syscalls; i++)
#define for_each_syscall(i) \
	for (i = 0; i < max_nr_syscalls; i++)

#endif	/* _TRINITY_SYSCALL_H */
