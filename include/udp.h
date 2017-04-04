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

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITING,

	CHILD_SPAWNED,
	CHILD_EXITED,
	CHILD_SIGNALLED,

	OBJ_CREATED_FILE,
	OBJ_CREATED_MAP,

	MAX_LOGMSGTYPE,
};

struct trinity_msghdr {
	enum logmsgtypes type;
	pid_t pid;
};

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

struct trinity_msgobjhdr {
	enum logmsgtypes type;
	pid_t pid;
	bool global;
	void *address;
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
