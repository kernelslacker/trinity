#ifndef _TRINITY_SYSCALL_H
#define _TRINITY_SYSCALL_H 1

enum argtype {
	ARG_FD = 1,
	ARG_LEN = 2,
	ARG_ADDRESS = 3,
	ARG_ADDRESS2 = 4,
	ARG_NON_NULL_ADDRESS = 5,
	ARG_PID = 6,
	ARG_RANGE = 7,
	ARG_OP = 8,
	ARG_LIST = 9,
	ARG_RANDPAGE = 10,
	ARG_CPU = 11,
	ARG_PATHNAME = 12,
};

struct arglist {
	unsigned int num;
	unsigned int values[1024];
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

	const unsigned int low1range, hi1range;
	const unsigned int low2range, hi2range;
	const unsigned int low3range, hi3range;
	const unsigned int low4range, hi4range;
	const unsigned int low5range, hi5range;
	const unsigned int low6range, hi6range;

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
extern struct syscalltable *syscalls;
extern struct syscalltable *syscalls_32bit;
extern struct syscalltable *syscalls_64bit;

extern unsigned long long syscallcount;
extern unsigned int max_nr_syscalls;
extern unsigned int max_nr_32bit_syscalls;
extern unsigned int max_nr_64bit_syscalls;

extern unsigned char use_32bit;
extern unsigned char use_64bit;

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)
#define BORING (1<<3)
#define ACTIVE (1<<4)

void setup_syscall_tables(void);
int search_syscall_table(struct syscalltable *table, unsigned int nr_syscalls, const char *arg);
int validate_specific_syscall(struct syscalltable *table, int call);
void mark_all_syscalls_active(void);
void toggle_syscall(char *arg, unsigned char state);
void dump_syscall_tables(void);
int setup_syscall_group(unsigned int desired_group);
int validate_syscall_tables(void);

#endif	/* _TRINITY_SYSCALL_H */
