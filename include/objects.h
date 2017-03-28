#pragma once

#include "futex.h"
#include "list.h"
#include "maps.h"
#include "object-types.h"
#include "socketinfo.h"
#include "sysv-shm.h"
#include "trinity.h"
#include "types.h"

struct fileobj {
	const char *filename;
	int flags;
	int fd;
	bool fopened;
	int fcntl_flags;
};

struct bpfobj {
	u32 map_type;
	int map_fd;
};

struct pipeobj {
	int fd;
	int flags;
	bool reader;
};

struct perfobj {
	void * eventattr;
	int fd;
	pid_t pid;
	int cpu;
	int group_fd;
	unsigned long flags;
};

struct epollobj {
	int fd;
	bool create1;
	int flags;
};

struct eventfdobj {
	int fd;
	int count;
	int flags;
};

struct timerfdobj {
	int fd;
	int clockid;
	int flags;
};

struct memfdobj {
	int fd;
	char *name;
	int flags;
};

struct inotifyobj {
	int fd;
	int flags;
};

struct object {
	struct list_head list;
	union {
		struct map map;

		struct fileobj fileobj;

		struct pipeobj pipeobj;

		struct perfobj perfobj;

		struct epollobj epollobj;

		struct eventfdobj eventfdobj;

		struct timerfdobj timerfdobj;

		struct fileobj testfileobj;

		struct memfdobj memfdobj;

		int drmfd;

		struct inotifyobj inotifyobj;

		int userfaultfd;

		int fanotifyfd;

		struct bpfobj bpfobj;
		int bpf_prog_fd;

		struct socketinfo sockinfo;

		struct __lock lock; /* futex */

		struct sysv_shm sysv_shm;
	};
};

struct objhead {
	struct list_head *list;
	unsigned int num_entries;
	unsigned int max_entries;
	void (*destroy)(struct object *obj);
	void (*dump)(struct object *obj);
};

#define OBJ_GLOBAL 0
#define OBJ_LOCAL 1

struct object * alloc_object(void);
void add_object(struct object *obj, bool global, enum objecttype type);
void destroy_object(struct object *obj, bool global, enum objecttype type);
void destroy_global_objects(void);
void init_object_lists(bool global);
struct object * get_random_object(enum objecttype type, bool global);
bool objects_empty(enum objecttype type);
struct objhead * get_objhead(bool global, enum objecttype type);
void prune_objects(void);
