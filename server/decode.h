#pragma once

//#include "trinity.h"
#include "udp.h"

struct msgfunc {
	char * (*func)(char *buf);
};

extern const struct msgfunc decodefuncs[MAX_LOGMSGTYPE];

char *decode_child_spawned(char *buf);
char *decode_child_exited(char *buf);
char *decode_child_signalled(char *buf);

char *decode_main_started(char *buf);
char *decode_main_exiting(char *buf);
char *decode_reseed(char *buf);

char *decode_obj_created_file(char *buf);
char *decode_obj_created_map(char *buf);
char *decode_obj_created_pipe(char *buf);
char *decode_obj_created_perf(char *buf);
char *decode_obj_created_epoll(char *buf);
char *decode_obj_created_eventfd(char *buf);
char *decode_obj_created_timerfd(char *buf);
char *decode_obj_created_testfile(char *buf);
char *decode_obj_created_memfd(char *buf);
char *decode_obj_created_drm(char *buf);
char *decode_obj_created_inotify(char *buf);
char *decode_obj_created_userfault(char *buf);
char *decode_obj_created_fanotify(char *buf);
char *decode_obj_created_bpfmap(char *buf);
char *decode_obj_created_socket(char *buf);
char *decode_obj_created_futex(char *buf);
char *decode_obj_created_shm(char *buf);
char *decode_obj_destroyed(char *buf);

char *decode_syscalls_enabled(char *buf);
char *decode_syscall_prep(char *buf);
char *decode_syscall_result(char *buf);
