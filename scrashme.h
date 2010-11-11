#ifndef _SCRASHME_H
#define _SCRASHME_H 1


#ifndef S_SPLINT_S
#define __unused __attribute((unused))
#else
#define __unused /*@unused@*/
#endif


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

	unsigned int lowrange;
	unsigned int hirange;
};

extern struct syscalltable *syscalls;

#define ARG_FD	1
#define ARG_LEN	2
#define ARG_ADDRESS 3
#define ARG_PID 4
#define ARG_RANGE 5

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)

void generic_sanitise(int call,
	unsigned long *a1, unsigned long *a2, unsigned long *a3,
	unsigned long *a4, unsigned long *a5, unsigned long *a6);

unsigned long rand64();

extern unsigned int page_size;
extern char *useraddr;

#define RED	"[1;31m"
#define GREEN	"[1;32m"
#define YELLOW	"[1;33m"
#define BLUE	"[1;34m"
#define MAGENTA	"[1;35m"
#define CYAN	"[1;36m"
#define WHITE	"[1;37m"

#endif	/* _SCRASHME_H */


