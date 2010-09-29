#ifndef _SCRASHME_H
#define _SCRASHME_H 1

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
	int flags;

	int arg1type;
	int arg2type;
	int arg3type;
	int arg4type;
	int arg5type;
	int arg6type;
};

#define ARG_FD	1

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)

extern int page_size;
extern char *useraddr;

#endif	/* _SCRASHME_H */
