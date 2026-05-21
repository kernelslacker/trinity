#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
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
	/*
	 * Bitmask of OBJ_FLAG_* (see include/canary.h).  Currently
	 * only OBJ_FLAG_NO_WRITE is defined; the field is sized as a
	 * full word so future bits don't widen the struct again.
	 * Default zero — unset by alloc_shared_obj's memset for
	 * bump-allocated fresh chunks, and by the testfile/pagecache
	 * providers which never touch this field.  Producers that
	 * need the flag set assign it explicitly at object publish.
	 */
	unsigned int obj_flags;
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
	/* Stable identity assigned at allocation time, used as the index
	 * into the per-process child_armed_epfds[] bitmap in fds/epoll.c
	 * that tracks whether THIS process has already issued the
	 * EPOLL_CTL_ADD population for this epfd.  Written exactly once
	 * by the parent (under the alloc_shared_obj/add_object thaw
	 * bracket) and read-only thereafter — children never store into
	 * the frozen shm region. */
	unsigned int pool_idx;
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

struct signalfdobj {
	int fd;
};

struct mountfdobj {
	int fd;
};

struct cgroupfdobj {
	int fd;
};

struct watch_queueobj {
	int fd;		/* exposed read end (the watch_queue consumer) */
	int peer_fd;	/* held write end; closed in destructor to avoid leak */
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

struct landlockobj {
	int fd;
};

struct kvmsysobj {
	int fd;
	int api_version;
};

struct kvmvmobj {
	int fd;
	int parent_sysfd;
	int nr_vcpus;
	int nr_devices;
};

struct kvmvcpuobj {
	int fd;
	int parent_vmfd;
	int vcpu_id;
	void *kvm_run;
	size_t kvm_run_size;
};

struct aioobj {
	unsigned long ctx;
};

struct keyserialobj {
	int32_t serial;
};

struct timeridobj {
	int32_t tid;
};

struct pidobj {
	pid_t pid;
};

struct sysvsemobj {
	int semid;
};

struct sysvmsgobj {
	int msqid;
};

struct sharedfutexobj {
	uint32_t *word;	/* points into shared region alloc'd in create_shared_futex_pool */
};

struct object {
	/*
	 * Per-obj pool tag.  First field so consumers can spot-check
	 * obj->obj_type before dereferencing any union member.  Set by
	 * add_object() once the obj has passed the fd-bound gate and is
	 * about to enter a pool, and naturally invalidated back to
	 * OBJ_NONE (the enum-zero sentinel) by release_obj()'s memset
	 * when an obj is torn down or rejected at insert time, so a
	 * stale pointer into a recycled chunk reads as OBJ_NONE and
	 * fails the canonical objpool_check() below.
	 */
	enum objecttype obj_type;
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

		struct signalfdobj signalfdobj;

		struct mountfdobj mountfdobj;

		struct cgroupfdobj cgroupfdobj;

		struct watch_queueobj watch_queueobj;

		struct iommufdobj iommufdobj;

		struct fsctxobj fsctxobj;

		struct io_uringobj io_uringobj;

		struct landlockobj landlockobj;

		struct kvmsysobj kvmsysobj;

		struct kvmvmobj kvmvmobj;

		struct kvmvcpuobj kvmvcpuobj;

		struct aioobj aioobj;

		struct keyserialobj keyserialobj;

		struct timeridobj timeridobj;

		struct pidobj pidobj;

		struct sysvsemobj sysvsemobj;

		struct sysvmsgobj sysvmsgobj;

		struct socketinfo sockinfo;

		struct __lock lock; /* futex */

		struct sharedfutexobj sharedfutexobj;

		struct sysv_shm sysv_shm;
	};
};

/*
 * Per-objhead fd→object hash slot for OBJ_LOCAL pools.  Open-addressing
 * with linear probing: fd == -1 marks an empty slot.  Sized to a fixed
 * power-of-two (LOCAL_FD_HASH_SIZE) chosen comfortably above any plausible
 * per-(child, type) entry count so the load factor stays low and probes
 * resolve in one or two steps.
 */
struct local_fd_hash_slot {
	int fd;
	struct object *obj;
};

/*
 * Power-of-two slot count for the per-OBJ_LOCAL fd→object hash.  Sized
 * above the realistic upper bound of entries any single (child, type) pool
 * accumulates so open-addressing probes settle in O(1) at the typical
 * load factors observed in fuzz runs.
 */
#define LOCAL_FD_HASH_SIZE	1024

struct objhead {
	struct object **array;		/* parallel array for O(1) random access */
	/*
	 * Per-objhead fd→object hash for OBJ_LOCAL fd-typed pools.  Lazily
	 * allocated in the child's private heap on the first add_object()
	 * insert and kept in sync by add_object()/__destroy_object() on every
	 * slot mutation.  find_local_object_by_fd() consults this instead of
	 * walking head->array linearly, which collapses an O(n) scan with
	 * one cache line per slot into an O(1) probe.  Stays NULL for
	 * non-fd OBJ_LOCAL pools.
	 */
	struct local_fd_hash_slot *fd_hash;
	unsigned int num_entries;
	unsigned int array_capacity;
	unsigned int max_entries;
	void (*destroy)(struct object *obj);
	void (*dump)(struct object *obj, enum obj_scope scope);
};

/*
 * Iterate the parallel array of an objhead.
 *
 * Walks head->array[0..num_entries) and yields each non-NULL slot as
 * `obj`, with `idx` set to the slot index.  NULL slots are skipped:
 * __destroy_object()'s swap-with-last leaves the previously-last slot
 * NULL until num_entries is decremented, so a walker can legitimately
 * observe a transient NULL mid-removal in the owning process.
 *
 * The pool lives entirely in the owning process's private heap
 * post-Stage-5; head->num_entries and head->array are not reachable
 * from any other address space, so the snapshot is just a hoist
 * convenience for the compiler and there are no TOCTOU windows to
 * defend against.
 *
 * Usage:
 *	struct object *obj;
 *	unsigned int idx;
 *
 *	for_each_obj(head, obj, idx) {
 *		... use obj ...
 *	}
 */
struct __for_each_obj_state {
	unsigned int n_snap;
	struct object **array_snap;
	int do_iter;
};

void __for_each_obj_init(struct objhead *head,
			 struct __for_each_obj_state *s);

#define for_each_obj(head, obj, idx)					\
	for (struct __for_each_obj_state __feo = { .do_iter = 1 };	\
	     __feo.do_iter &&						\
		     (__for_each_obj_init((head), &__feo), 1);		\
	     __feo.do_iter = 0)						\
		for ((idx) = 0; (idx) < __feo.n_snap; (idx)++)		\
			if (((obj) = __feo.array_snap[(idx)]) != NULL)

struct object * alloc_object(void) __must_check;
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

/*
 * Shallow-copy the parent's OBJ_GLOBAL pool into the owning child's
 * private heap.  Called from init_child() after the OBJ_LOCAL pool is
 * brought up and before the bring-up of any caller that resolves an
 * OBJ_GLOBAL objhead.  Allocates child->global_objects[MAX_OBJECT_TYPES]
 * and per-type slot arrays sized to the parent's current num_entries,
 * plus child-private copies of shm->fd_hash[] and shm->fd_live[].
 * Cross-process fd / mmap resources are inherited by fork; the
 * snapshot only duplicates the bookkeeping pointers that name them.
 */
void clone_global_objects_to_child(struct childdata *child);

struct object * get_random_object(enum objecttype type, enum obj_scope scope) __must_check;

/*
 * Canonical shape check before dereferencing an obj returned by
 * get_random_object().  Defends the fds/ and adjacent consumer
 * sites from the wild-obj-pointer class of failure catalogued in the
 * 2026-05-18 objpool shape-check audit: a slot the lockless picker
 * resolved to an address that happens to land in the user/heap VA
 * window but doesn't actually name a live obj of the expected pool
 * (typically because the parent destroyed the obj and the shared-heap
 * freelist recycled the chunk underneath the reader, or because
 * memory corruption stomped a slot pointer).
 *
 * Three layers, cheapest first:
 *   1. NULL — the lockless picker can return NULL legitimately on an
 *      empty pool, and consumers must skip such picks.
 *   2. VA-range — heap pointers land at >= 0x10000 and below the
 *      47-bit user/kernel boundary on every distro we exercise;
 *      anything outside that window can't be a real obj struct.
 *   3. Pool tag — obj->obj_type must equal the type the caller asked
 *      for.  Catches the cross-pool recycling case the VA-range gate
 *      cannot, and reads OBJ_NONE (== 0) for a free/zero'd chunk
 *      after release_obj()'s memset.
 *
 * Returns true if obj is safe to dereference as the expected type.
 */
static inline bool objpool_check(const struct object *obj,
				 enum objecttype expected)
{
	if (obj == NULL)
		return false;
	if ((uintptr_t)obj < 0x10000UL ||
	    (uintptr_t)obj >= 0x800000000000UL)
		return false;
	if (obj->obj_type != expected)
		return false;
	return true;
}

bool objects_empty(enum objecttype type);
bool objects_pool_empty(enum obj_scope scope, enum objecttype type);
struct objhead * get_objhead(enum obj_scope scope, enum objecttype type) __must_check;
void prune_objects(void);
int fd_from_object(struct object *obj, enum objecttype type);
void set_object_fd(struct object *obj, enum objecttype type, int fd);
struct object *find_local_object_by_fd(enum objecttype type, int fd);
void remove_object_by_fd(int fd);

/* fd hash table for O(1) fd→object lookup */
#define FD_HASH_SIZE 4096	/* power of 2, must exceed max tracked fds */

/*
 * Cap on the parallel compact live-fd list (shm->fd_live[]) maintained
 * alongside fd_hash[].  The list lets refcount-auditor and other
 * "iterate every live fd" walkers skip the sparse-hash empty-slot
 * scan.  Sized to FD_HASH_SIZE so overflow is impossible by
 * construction (fd_hash_insert refuses past FD_HASH_SIZE entries
 * already), but the writer still gates on this cap and silently
 * drops overflow entries from the live list — the auditor is a
 * sampling consumer and tolerates a missed entry.
 */
#define FD_LIVE_MAX FD_HASH_SIZE

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
