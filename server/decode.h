#pragma once

//#include "trinity.h"
#include "udp.h"

struct msgfunc {
	void (*func)(char *buf);
};

extern const struct msgfunc decodefuncs[MAX_LOGMSGTYPE];

void decode_child_spawned(char *buf);
void decode_child_exited(char *buf);
void decode_child_signalled(char *buf);

void decode_main_started(char *buf);
void decode_main_exiting(char *buf);
void decode_reseed(char *buf);

void decode_obj_created_file(char *buf);
void decode_obj_created_map(char *buf);
void decode_obj_created_pipe(char *buf);
void decode_obj_created_perf(char *buf);
void decode_obj_created_epoll(char *buf);
void decode_obj_created_eventfd(char *buf);
void decode_obj_created_timerfd(char *buf);
void decode_obj_created_testfile(char *buf);
void decode_obj_created_memfd(char *buf);
void decode_obj_created_drm(char *buf);
void decode_obj_created_inotify(char *buf);
void decode_obj_created_userfault(char *buf);
void decode_obj_created_fanotify(char *buf);
void decode_obj_created_bpfmap(char *buf);
void decode_obj_created_socket(char *buf);
void decode_obj_created_futex(char *buf);
void decode_obj_created_shm(char *buf);
void decode_obj_destroyed(char *buf);

void decode_syscalls_enabled(char *buf);
void decode_syscall_prep(char *buf);
void decode_syscall_result(char *buf);
