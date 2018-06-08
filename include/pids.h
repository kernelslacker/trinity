#pragma once

#include <sys/types.h>
#include "child.h"
#include "types.h"

extern pid_t *pids;
extern pid_t mainpid;

#define for_each_child(i)	for (i = 0; i < max_children; i++)

#define CHILD_NOT_FOUND -1
#define EMPTY_PIDSLOT -1

bool pid_alive(pid_t pid);
int find_childno(pid_t mypid);
bool pidmap_empty(void);
void dump_childnos(void);
int pid_is_valid(pid_t);
void pids_init(void);
