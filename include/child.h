#ifndef _CHILD_H
#define _CHILD_H 1

#include <sys/types.h>

int child_process(int childno);
long mkcall(int child);
void do_syscall_from_child(void);

void init_child(int childno);

void reap_child(pid_t childpid);

void check_parent_pid(void);

int do_random_syscalls(int childno);

#endif	/* _CHILD_H */
