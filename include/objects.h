#pragma once

#include "list.h"
#include "maps.h"
#include "trinity.h"

enum objecttype {
	OBJ_MMAP,
	OBJ_FD_PIPE,
	OBJ_FD_FILE,
	OBJ_FD_PERF,
	OBJ_FD_EPOLL,
	OBJ_FD_EVENTFD,
	OBJ_FD_TIMERFD,
	MAX_OBJECT_TYPES,
};

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
	};
};

struct objhead {
	struct list_head *list;
	unsigned int num_entries;
	void (*destroy)(struct object *obj);
};

#define OBJ_GLOBAL 0
#define OBJ_LOCAL 1

struct object * alloc_object(void);
void add_object(struct object *obj, bool global, enum objecttype type);
void destroy_object(struct object *obj, bool global, enum objecttype type);
void init_object_lists(bool global);
struct object * get_random_object(enum objecttype type, bool global);
