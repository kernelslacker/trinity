#pragma once

#include <stdint.h>
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
	bool pagecache_backed;
	bool is_setuid;
	int fcntl_flags;
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

struct memfd_secretobj {
	int fd;
	int flags;
};

struct inotifyobj {
	int fd;
	int flags;
};

struct userfaultobj {
	int fd;
	int flags;
};

struct fanotifyobj {
	int fd;
	int flags;
	int eventflags;
};

struct bpfobj {
	u32 map_type;
	int map_fd;
};

struct bpfprogobj {
	int fd;
	u32 prog_type;
};

struct bpflinkobj {
	int fd;
	u32 attach_type;
};

struct bpfbtfobj {
	int fd;
};

struct pidfdobj {
	int fd;
	pid_t pid;
};

struct mqobj {
	int fd;
	char name[8];	/* "/trinN\0" */
};

struct seccomp_notifobj {
	int fd;
};

struct iommufdobj {
	int fd;
};

struct fsctxobj {
	int fd;
};

struct io_uringobj {
	int fd;
	unsigned int setup_flags;
	void *sq_ring;		/* mmap'd SQ ring, NULL if not mapped */
	void *sqes;		/* mmap'd SQE array */
	size_t sq_ring_sz;	/* mmap size for munmap */
	size_t sqes_sz;
	unsigned int sq_entries;
	unsigned int off_head;
	unsigned int off_tail;
	unsigned int off_mask;
	unsigned int off_array;
};

struct io_uringobj *get_io_uring_ring(void);

unsigned long get_random_aio_ctx(void);

struct landlockobj {
	int fd;
};

struct aioobj {
	unsigned long ctx;
};

struct object {
	unsigned int array_idx;		/* index in objhead->array */
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

		struct memfd_secretobj memfd_secretobj;

		int drmfd;

		struct inotifyobj inotifyobj;

		struct userfaultobj userfaultobj;

		struct fanotifyobj fanotifyobj;

		struct bpfobj bpfobj;

		struct bpfprogobj bpfprogobj;

		struct bpflinkobj bpflinkobj;

		struct bpfbtfobj bpfbtfobj;

		struct pidfdobj pidfdobj;

		struct mqobj mqobj;

		struct seccomp_notifobj seccomp_notifobj;

		struct iommufdobj iommufdobj;

		struct fsctxobj fsctxobj;

		struct io_uringobj io_uringobj;

		struct landlockobj landlockobj;

		struct aioobj aioobj;

		struct socketinfo sockinfo;

		struct __lock lock; /* futex */

		struct sysv_shm sysv_shm;
	};
};

struct objhead {
	struct object **array;		/* parallel array for O(1) random access */
	unsigned int num_entries;
	unsigned int array_capacity;
	unsigned int max_entries;
	void (*destroy)(struct object *obj);
	void (*dump)(struct object *obj, enum obj_scope scope);
	/*
	 * If true, obj structs for this (scope=OBJ_GLOBAL) type came from
	 * alloc_shared_obj() and __destroy_object() must release them via
	 * free_shared_obj() rather than free().  Set per-type by an
	 * fd_provider/REG_GLOBAL_OBJ init that opted into shared-heap
	 * allocation.  Ignored for OBJ_LOCAL pools — child-private objs
	 * always come from zmalloc().
	 */
	bool shared_alloc;
};

/*
 * Cap for the number of objects on a global objhead list.  Allocated up
 * front in shm so children never need to follow a parent-private array
 * pointer.  See the matching comment above add_object().
 */
#define GLOBAL_OBJ_MAX_CAPACITY	1024

/*
 * Iterate the parallel array of an objhead.
 *
 * Walks head->array[0..num_entries) and yields each non-NULL slot as
 * `obj`, with `idx` set to the slot index.  NULL slots are skipped:
 * __destroy_object()'s swap-with-last leaves the previously-last slot
 * NULL until num_entries is decremented, so a walker that doesn't hold
 * shm->objlock can legitimately observe a transient NULL mid-removal.
 *
 * The (idx < array_capacity) bound is a defence against a corrupt
 * num_entries (a stray write past the cap): without it a torn count
 * would walk off the end of the array.  array_capacity is fixed at
 * init time for OBJ_GLOBAL pools (GLOBAL_OBJ_MAX_CAPACITY) and never
 * shrinks for OBJ_LOCAL.
 *
 * No atomics are emitted by the macro.  Callers that need a stable
 * snapshot of num_entries (lockless child reads of an OBJ_GLOBAL pool)
 * must take it themselves with __ATOMIC_ACQUIRE before iterating, the
 * same way get_random_object() does today.
 *
 * Usage:
 *	struct object *obj;
 *	unsigned int idx;
 *
 *	for_each_obj(head, obj, idx) {
 *		... use obj ...
 *	}
 */
#define for_each_obj(head, obj, idx)					\
	for ((idx) = 0;							\
	     (idx) < (head)->num_entries &&				\
	     (idx) < (head)->array_capacity;				\
	     (idx)++)							\
		if (((obj) = (head)->array[idx]) != NULL)

struct object * alloc_object(void);
void add_object(struct object *obj, enum obj_scope scope, enum objecttype type);
void destroy_object(struct object *obj, enum obj_scope scope, enum objecttype type);
void destroy_global_objects(void);

/*
 * Self-registration for global object initializers.  Each object subsystem
 * calls REG_GLOBAL_OBJ() once (at program startup, via a constructor) to
 * register its init function.  init_global_objects() iterates the list and
 * calls every registered init in registration order.
 *
 * This mirrors the REG_FD_PROV() pattern used by fd providers and removes
 * the need for trinity.c to maintain a manual object_init_table.
 */
struct global_obj_entry {
	struct list_head list;
	const char *name;
	void (*init)(void);
};

void register_global_obj_init(struct global_obj_entry *entry);
void init_global_objects(void);
struct childdata;
void init_object_lists(enum obj_scope scope, struct childdata *child);
struct object * get_random_object(enum objecttype type, enum obj_scope scope);
bool objects_empty(enum objecttype type);
void validate_global_objects(void);
struct objhead * get_objhead(enum obj_scope scope, enum objecttype type);
void prune_objects(void);
int fd_from_object(struct object *obj, enum objecttype type);
void set_object_fd(struct object *obj, enum objecttype type, int fd);
struct object *find_local_object_by_fd(enum objecttype type, int fd);
void remove_object_by_fd(int fd);

/* fd hash table for O(1) fd→object lookup */
#define FD_HASH_SIZE 4096	/* power of 2, must exceed max tracked fds */

struct fd_hash_entry {
	int fd;			/* -1 = empty slot */
	enum objecttype type;
	struct object *obj;
	/*
	 * Bumped on every state-change for this slot (fresh insert, removal).
	 * Preserved when an entry is merely rehashed to a different slot
	 * because the entry's identity is unchanged.  Children cache this
	 * value alongside an fd to detect close-then-reopen-to-same-fd
	 * recycling without a syscall probe.
	 */
	uint32_t gen;
};

void fd_hash_init(void);
bool fd_hash_insert(int fd, struct object *obj, enum objecttype type);
void fd_hash_remove(int fd);
struct fd_hash_entry *fd_hash_lookup(int fd);

#define REG_GLOBAL_OBJ(_tag, _init_fn)					\
	static struct global_obj_entry					\
		__global_obj_entry_##_tag = {				\
		.name = #_tag,						\
		.init = (_init_fn),					\
	};								\
	static void __attribute__((constructor))			\
	__register_global_obj_##_tag(void)				\
	{								\
		register_global_obj_init(&__global_obj_entry_##_tag);	\
	}
