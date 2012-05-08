#ifndef _TRINITY_SYSCALL_H
#define _TRINITY_SYSCALL_H 1

struct arglist {
	unsigned int num;
	unsigned int values[1024];
};

struct syscall {
	void (*sanitise)(
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *);
	void (*post)(int);

	unsigned int number;
	const char name[80];
	unsigned int num_args;
	unsigned int flags;

	unsigned int arg1type;
	unsigned int arg2type;
	unsigned int arg3type;
	unsigned int arg4type;
	unsigned int arg5type;
	unsigned int arg6type;

	const char *arg1name;
	const char *arg2name;
	const char *arg3name;
	const char *arg4name;
	const char *arg5name;
	const char *arg6name;

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

	unsigned int group;
	int rettype;
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

#define ARG_FD		1
#define ARG_LEN		2
#define ARG_ADDRESS	3
#define ARG_PID		4
#define ARG_RANGE	5
#define ARG_LIST	6
#define ARG_RANDPAGE	7	/* ->sanitise will scribble over this. */
#define ARG_CPU		8
#define ARG_PATHNAME	9

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)
#define BORING (1<<3)

#endif	/* _TRINITY_SYSCALL_H */
