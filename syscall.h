#ifndef _TRINITY_SYSCALL_H
#define _TRINITY_SYSCALL_H 1

enum argtype {
	ARG_FD,
	ARG_LEN,
	ARG_ADDRESS,
	ARG_PID,
	ARG_RANGE,
	ARG_LIST,
	ARG_RANDPAGE,
	ARG_CPU,
	ARG_PATHNAME,
};

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

	enum argtype arg1type;
	enum argtype arg2type;
	enum argtype arg3type;
	enum argtype arg4type;
	enum argtype arg5type;
	enum argtype arg6type;

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

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)
#define BORING (1<<3)

#endif	/* _TRINITY_SYSCALL_H */
