#pragma once

#include <sys/types.h>
#include <unistd.h>
#include "exit.h"
#include "maps.h"
#include "pathnames.h"
#include "socketinfo.h"
#include "types.h"

#define TRINITY_LOG_PORT 6665

#define TRINITY_UDP_VERSION 0

extern int logging_enabled;

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITING,

	CHILD_SPAWNED,
	CHILD_EXITED,
	CHILD_SIGNALLED,

	OBJ_CREATED_FILE,
	OBJ_CREATED_MAP,
	OBJ_CREATED_PIPE,
	OBJ_CREATED_PERF,
	OBJ_CREATED_EPOLL,
	OBJ_CREATED_EVENTFD,
	OBJ_CREATED_TIMERFD,
	OBJ_CREATED_TESTFILE,
	OBJ_CREATED_MEMFD,
	OBJ_CREATED_DRM,
	OBJ_CREATED_INOTIFY,
	OBJ_CREATED_USERFAULT,
	OBJ_CREATED_FANOTIFY,
	OBJ_CREATED_BPFMAP,
	OBJ_CREATED_SOCKET,
	OBJ_CREATED_FUTEX,
	OBJ_CREATED_SHM,

	OBJ_DESTROYED,

	SYSCALLS_ENABLED,
	SYSCALL_PREP,
	SYSCALL_RESULT,

	RESEED,

	MAX_LOGMSGTYPE,
};

struct trinity_msghdr {
	enum logmsgtypes type;
	pid_t pid;
};

struct trinity_msgobjhdr {
	enum logmsgtypes type;
	pid_t pid;
	bool global;
	void *address;
};

struct trinity_msgchildhdr {
	enum logmsgtypes type;
	struct timespec tp;
	pid_t pid;
	int childno;
};

void init_msghdr(struct trinity_msghdr *hdr, enum logmsgtypes type);
void init_msgobjhdr(struct trinity_msgobjhdr *hdr, enum logmsgtypes type, bool global, struct object *obj);
void init_msgchildhdr(struct trinity_msgchildhdr *hdr, enum logmsgtypes type, pid_t pid, int childno);

void init_udp_logging(char *optarg);
void shutdown_udp_logging(void);
void sendudp(char *buffer, size_t len);

struct msg_mainstarted {
	struct trinity_msghdr hdr;
	void * shm_begin;
	void * shm_end;
	unsigned int initial_seed;
};

struct msg_mainexiting {
	struct trinity_msghdr hdr;
	enum exit_reasons reason;
};

struct msg_childspawned {
	struct trinity_msgchildhdr hdr;
};

struct msg_childexited {
	struct trinity_msgchildhdr hdr;
	unsigned long op_nr;
};

struct msg_childsignalled {
	struct trinity_msgchildhdr hdr;
	int sig;
	unsigned long op_nr;
};

struct msg_objcreatedfile {
	struct trinity_msgobjhdr hdr;
	char filename[MAX_PATH_LEN];
	int flags;
	int fd;
	bool fopened;
	int fcntl_flags;
};

struct msg_objcreatedmap {
	struct trinity_msgobjhdr hdr;
	void *start;
	char name[MAPS_NAME_MAX_LEN];
	int prot;
	unsigned char type;
	unsigned long size;
};

struct msg_objcreatedpipe {
	struct trinity_msgobjhdr hdr;
	int fd;
	int flags;
	bool reader;
};

struct msg_objcreatedperf {
	struct trinity_msgobjhdr hdr;
	int fd;
	pid_t pid;
	int cpu;
	int group_fd;
	unsigned long flags;
	int eventattrsize;
	// eventattr bytestream follows immediately afterwards.
	char eventattr[];
};

struct msg_objcreatedepoll {
	struct trinity_msgobjhdr hdr;
	int fd;
	bool create1;
	int flags;
};

struct msg_objcreatedeventfd {
	struct trinity_msgobjhdr hdr;
	int fd;
	int count;
	int flags;
};

struct msg_objcreatedtimerfd {
	struct trinity_msgobjhdr hdr;
	int fd;
	int clockid;
	int flags;
};

struct msg_objcreatedmemfd {
	struct trinity_msgobjhdr hdr;
	int fd;
	char name[MAX_PATH_LEN];
	int flags;
};

struct msg_objcreateddrm {
	struct trinity_msgobjhdr hdr;
	int fd;
};

struct msg_objcreatedinotify {
	struct trinity_msgobjhdr hdr;
	int fd;
	int flags;
};

struct msg_objcreateduserfault {
	struct trinity_msgobjhdr hdr;
	int fd;
	int flags;
};

struct msg_objcreatedfanotify {
	struct trinity_msgobjhdr hdr;
	int fd;
	int flags;
	int eventflags;
};

struct msg_objcreatedbpfmap {
	struct trinity_msgobjhdr hdr;
	int map_type;
	int map_fd;
};

struct msg_objcreatedsocket {
	struct trinity_msgobjhdr hdr;
	struct socketinfo si;
};

struct msg_objcreatedfutex {
	struct trinity_msgobjhdr hdr;
	int futex;
	pid_t owner;
};

struct msg_objcreatedshm {
	struct trinity_msgobjhdr hdr;
	void *ptr;
	int id;
	size_t size;
	int flags;
};

struct msg_objdestroyed {
	struct trinity_msgobjhdr hdr;
};

struct msg_syscallsenabled {
	struct trinity_msghdr hdr;
	unsigned int nr_enabled;
	bool arch_is_biarch;	// whether capable
	bool is_64;		// whether the list in this msg is 64bit/32bit
	int entries[];
};

struct msg_syscallprep {
	struct trinity_msgchildhdr hdr;
	unsigned long sequence_nr;
	unsigned int nr;
	bool is32bit;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
};

struct msg_syscallresult {
	struct trinity_msgchildhdr hdr;
	unsigned long sequence_nr;
	long retval;
	int errno_post;
};

struct msg_reseed {
	struct trinity_msghdr hdr;
	unsigned int new_seed;
};
