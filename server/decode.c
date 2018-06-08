#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "decode.h"

const struct msgfunc decodefuncs[MAX_LOGMSGTYPE] = {
	[MAIN_STARTED] = { decode_main_started },
	[MAIN_EXITING] = { decode_main_exiting },
	[CHILD_SPAWNED] = { decode_child_spawned },
	[CHILD_EXITED] = { decode_child_exited },
	[CHILD_SIGNALLED] = { decode_child_signalled },
	[OBJ_CREATED_FILE] = { decode_obj_created_file },
	[OBJ_CREATED_MAP] = { decode_obj_created_map },
	[OBJ_CREATED_PIPE] = { decode_obj_created_pipe },
	[OBJ_CREATED_PERF] = { decode_obj_created_perf },
	[OBJ_CREATED_EPOLL] = { decode_obj_created_epoll },
	[OBJ_CREATED_EVENTFD] = { decode_obj_created_eventfd },
	[OBJ_CREATED_TIMERFD] = { decode_obj_created_timerfd },
	[OBJ_CREATED_TESTFILE] = { decode_obj_created_testfile },
	[OBJ_CREATED_MEMFD] = { decode_obj_created_memfd },
	[OBJ_CREATED_DRM] = { decode_obj_created_drm },
	[OBJ_CREATED_INOTIFY] = { decode_obj_created_inotify },
	[OBJ_CREATED_USERFAULT] = { decode_obj_created_userfault },
	[OBJ_CREATED_FANOTIFY] = { decode_obj_created_fanotify },
	[OBJ_CREATED_BPFMAP] = { decode_obj_created_bpfmap },
	[OBJ_CREATED_SOCKET] = { decode_obj_created_socket },
	[OBJ_CREATED_FUTEX] = { decode_obj_created_futex },
	[OBJ_CREATED_SHM] = { decode_obj_created_shm },
	[OBJ_DESTROYED] = { decode_obj_destroyed },
	[SYSCALLS_ENABLED] = { decode_syscalls_enabled },
	[SYSCALL_PREP] = { decode_syscall_prep },
	[SYSCALL_RESULT] = { decode_syscall_result },
	[RESEED] = { decode_reseed },
};
