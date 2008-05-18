#ifndef _SCRASHME_H
#define _SCRASHME_H 1

struct syscalltable {
	char name[80];
	void (*sanitise)(
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *,
		unsigned long *);
	int flags;
};

#define CAPABILITY_CHECK 1
#define AVOID_SYSCALL 2

extern int page_size;
extern char *useraddr;

#endif	/* _SCRASHME_H */
