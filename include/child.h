#pragma once

#include <sys/types.h>

extern int this_child;

extern unsigned int max_children;

void child_process(int childno);
long mkcall(int child);
void do_syscall_from_child(void);

void init_child(int childno);

void reap_child(pid_t childpid);

int child_random_syscalls(int childno);
int child_read_all_files(int childno);
