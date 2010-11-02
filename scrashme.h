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
	int flags;

	int arg1type;
	int arg2type;
	int arg3type;
	int arg4type;
	int arg5type;
	int arg6type;

	char *arg1name;
	char *arg2name;
	char *arg3name;
	char *arg4name;
	char *arg5name;
	char *arg6name;
};

extern struct syscalltable *syscalls;

#define ARG_FD	1
#define ARG_LEN	2
#define ARG_ADDRESS 3

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)

void generic_sanitise(int call,
	unsigned long *a1, unsigned long *a2, unsigned long *a3,
	unsigned long *a4, unsigned long *a5, unsigned long *a6);

extern int page_size;
extern char *useraddr;

#define RED	"[1;31m"
#define GREEN	"[1;32m"
#define YELLOW	"[1;33m"
#define BLUE	"[1;34m"
#define MAGENTA	"[1;35m"
#define CYAN	"[1;36m"
#define WHITE	"[1;37m"

#endif	/* _SCRASHME_H */


