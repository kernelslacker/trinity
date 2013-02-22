#ifndef _CHILD_H
#define _CHILD_H 1

#include <sys/types.h>

int child_process(void);
long mkcall(int child);
void do_syscall_from_child(void);

void init_child(void);

void reap_child(pid_t childpid);

#endif	/* _CHILD_H */
