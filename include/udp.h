#pragma once

#include <sys/types.h>
#include <unistd.h>
#include "exit.h"
#include "maps.h"
#include "pathnames.h"
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

void init_msghdr(struct trinity_msghdr *hdr, enum logmsgtypes type);
void init_msgobjhdr(struct trinity_msgobjhdr *hdr, enum logmsgtypes type, bool global, struct object *obj);
void init_childmsghdr(struct trinity_msghdr *hdr, enum logmsgtypes type, pid_t pid);

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

struct msg_mainstarted {
	struct trinity_msghdr hdr;
	unsigned int num_children;
	void * shm_begin;
	void * shm_end;
};

struct msg_mainexiting {
	struct trinity_msghdr hdr;
	enum exit_reasons reason;
};

struct msg_childspawned {
	struct trinity_msghdr hdr;
	int childno;
};

struct msg_childexited {
	struct trinity_msghdr hdr;
	int childno;
};

struct msg_childsignalled {
	struct trinity_msghdr hdr;
	int childno;
	int sig;

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
