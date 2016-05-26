#pragma once

#include "list.h"
#include "socketinfo.h"
#include "trinity.h"
#include "futex.h"
#include "object-types.h"
#include "maps.h"
#include "sysv-shm.h"

struct object {
	struct list_head list;
	union {
		struct map map;

		int pipefd;

		int filefd;

		int perffd;

		int epollfd;

		int eventfd;

		int timerfd;

		int testfilefd;

		int memfd;

		int drmfd;

		int inotifyfd;

		int userfaultfd;

		int fanotifyfd;

		int bpf_map_fd;

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
};

#define OBJ_GLOBAL 0
#define OBJ_LOCAL 1

void dump_objects(bool global, enum objecttype type);
struct object * alloc_object(void);
void add_object(struct object *obj, bool global, enum objecttype type);
void destroy_object(struct object *obj, bool global, enum objecttype type);
void destroy_global_objects(void);
void init_object_lists(bool global);
struct object * get_random_object(enum objecttype type, bool global);
bool objects_empty(enum objecttype type);
struct objhead * get_objhead(bool global, enum objecttype type);
void prune_objects(void);
