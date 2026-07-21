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

#include "kernel/fs.h"
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
	 * Default zero — alloc_object() returns zeroed memory, and the
	 * testfile/pagecache providers never touch this field.  Producers
	 * that need the flag set assign it explicitly at object publish.
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
	 * by the parent at object publish and read-only thereafter; each
	 * child arms its own inherited copy of the pool independently. */
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

struct bpftokenobj {
	int fd;
};

struct pidfdobj {
	int fd;
	pid_t pid;
};

/*
 * Sparse file: ftruncate-extended to `size`, with a single page of data
 * written at `data_offset` so the kernel sees exactly one data extent
 * bracketed by holes.  Consumers that exercise SEEK_DATA / SEEK_HOLE
 * read both fields to bias the syscall offset into the file so the
 * per-fs sparse-walk code actually runs instead of bailing on
 * pos >= i_size.
 */
struct sparsefileobj {
	const char *filename;
	int fd;
	off_t size;
	off_t data_offset;
};

struct mqobj {
	int fd;
	char name[24];	/* "/trin<pid>_<idx>\0" */
	/*
	 * Snapshot of the input fields of the create-time struct mq_attr
	 * (mq_curmsgs is runtime-only and not tracked).  Stored as plain
	 * longs instead of a struct mq_attr so objects.h does not have to
	 * pull <mqueue.h> -- that drags in <fcntl.h> and collides with the
	 * <linux/fcntl.h> already included by the pidfd syscall TUs.
	 * Downstream callers rehydrate a struct mq_attr by copying back.
	 */
	long attr_flags;
	long attr_maxmsg;
	long attr_msgsize;
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
	void *guest_ram;	/* seeded guest RAM (real-mode code @ gpa 0), or NULL */
	size_t guest_ram_size;
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

/*
 * Per-outstanding-iocb cookie published by post_io_submit on every
 * successful submission so io_cancel.c can pick a real (ctx, aio_data)
 * pair to cancel against, instead of always building a fresh local
 * iocb the kernel has no record of and EINVAL-ing on every call.
 * Lives in the per-child OBJ_LOCAL pool; the iocb itself is not
 * tracked (the kernel owns its lifetime once io_submit accepted it).
 */
struct aio_iocb_obj {
	unsigned long ctx;
	uint64_t aio_data;
};

struct keyserialobj {
	int32_t serial;
};

struct pkey_obj {
	int id;
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
	/*
	 * Per-obj identity tag drawn from a strictly monotonic per-pool
	 * counter (objhead->next_slot_version) at the successful
	 * add_object() return path.  First issued value is 1; the zero
	 * left behind by release_obj()'s memset is therefore a natural
	 * "this slot is dead" sentinel that never collides with a live
	 * stamp.  Consumers that race "stash a slot index, sleep, look
	 * the slot up again" against the pool's destroy+add cycle can
	 * snapshot this alongside the index and re-check via
	 * object_slot_alive() before dereferencing the obj they pulled
	 * back out of head->array.  No current consumers — this lands
	 * the field, bump and helper; migrations are separate commits.
	 */
	unsigned int slot_version;
	/*
	 * Provenance clock: snapshot of shm_published->fleet_op_count
	 * taken at the successful add_object() return path, i.e. the
	 * coarse fleet-wide op tick at which this obj first became
	 * visible in its pool.  Cold pre-stage field for an upcoming
	 * diag-drain consumer; no current reader.
	 */
	unsigned long publish_call_nr;
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

		struct bpftokenobj bpftokenobj;

		struct pidfdobj pidfdobj;

		struct mqobj mqobj;

		struct sparsefileobj sparsefileobj;

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

		struct aio_iocb_obj aio_iocb_obj;

		struct keyserialobj keyserialobj;

		struct pkey_obj pkey_obj;

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
	 * Strictly-monotonic counter bumped under the owning process's
	 * write every time head->array is freed and replaced (the OBJ_GLOBAL
	 * grow free(), the OBJ_LOCAL grow deferred_free_enqueue(), and the
	 * destroy_objects() teardown tracked_free_now()).  Lets the
	 * indexed-read helper detect a between-snapshot grow / teardown:
	 * snapshot the gen alongside the array pointer at pick time, do the
	 * load, then re-read the gen and discard the result on mismatch
	 * rather than letting an indexed read fall through to a chunk the
	 * deferred-free TTL has already handed back to glibc.  Pool-private
	 * single-writer (parent for OBJ_GLOBAL pre-fork, owning child for
	 * OBJ_LOCAL) so an unlocked load is sufficient; at 32 bits this
	 * wraps after ~4 billion grows, comfortably above anything an
	 * in-process fuzz run reaches.  Even a wrap would be benign --
	 * captured-gen != current-gen still trips the mismatch path for any
	 * grow that happens inside the snapshot window.
	 */
	unsigned int array_generation;
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
	/*
	 * Strictly-monotonic counter used to stamp obj->slot_version on
	 * every successful add_object() into this pool.  Pre-increment so
	 * the first issued value is 1 and zero (left by release_obj()'s
	 * memset on a freed obj) is reserved as a "never live" sentinel.
	 * Pool-private — single-writer is the owning process (the parent
	 * for OBJ_GLOBAL pre-fork, the owning child for OBJ_LOCAL).  At
	 * 32 bits this wraps after ~4 billion adds, which is well above
	 * anything an in-process fuzz run reaches; wrap to 0 would be
	 * benign in any case because consumers always compare a
	 * captured stamp against the current obj->slot_version literal,
	 * never against the counter itself.
	 */
	unsigned int next_slot_version;
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

/*
 * The state var is named __feo_<line> rather than __feo so two
 * for_each_obj invocations on adjacent lines (e.g. a nested walk
 * where the outer loop already has its own state) don't shadow
 * each other under -Wshadow.  __LINE__ is unique per top-level
 * macro expansion; the indirection through _FEO_CAT/_FEO_NAME
 * forces __LINE__ to expand before the token paste.
 */
#define _FEO_CAT(a, b)		a##b
#define _FEO_NAME(line)		_FEO_CAT(__feo_, line)
#define _FEO_STATE		_FEO_NAME(__LINE__)

#define for_each_obj(head, obj, idx)					\
	for (struct __for_each_obj_state _FEO_STATE = { .do_iter = 1 };	\
	     _FEO_STATE.do_iter &&					\
		     (__for_each_obj_init((head), &_FEO_STATE), 1);	\
	     _FEO_STATE.do_iter = 0)					\
		for ((idx) = 0; (idx) < _FEO_STATE.n_snap; (idx)++)	\
			if (((obj) = _FEO_STATE.array_snap[(idx)]) != NULL)

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
 * get_random_object().  Defends consumer sites from the wild-obj
 * pointer class of failure: a slot the lockless picker resolved to an
 * address that happens to land in the user/heap VA window but doesn't
 * actually name a live obj of the expected pool (typically because the
 * obj was destroyed and the deferred-free allocator recycled the
 * chunk underneath the reader, or because memory corruption stomped a
 * slot pointer).
 *
 * Three layers, cheapest first:
 *   1. NULL — the lockless picker can return NULL legitimately on an
 *      empty pool, and consumers must skip such picks.  Not counted
 *      as a wild-obj catch.
 *   2. VA-range — heap pointers land at >= 0x10000 and below the
 *      47-bit user/kernel boundary on every distro we exercise;
 *      anything outside that window can't be a real obj struct.
 *   3. Pool tag — obj->obj_type must equal the type the caller asked
 *      for.  Catches the cross-pool recycling case the VA-range gate
 *      cannot, and reads OBJ_NONE (== 0) for a free/zero'd chunk
 *      after release_obj()'s memset.
 *
 * Layers 2 and 3 bump shm->stats.diag.global_obj_uaf_caught so the rate of
 * caught wild/recycled obj resolutions is observable in the stats
 * surface.  Returns true if obj is safe to dereference as the
 * expected type.
 */
bool objpool_check(const struct object *obj, enum objecttype expected);

/*
 * Identity check for obj pointers cached across a window in which the
 * owning pool may have destroyed and re-added entries.  Capture
 * obj->slot_version at the moment a consumer first resolves the obj
 * (typically alongside obj->array_idx); pass the captured value back
 * at use time.  Returns true iff the obj at this address still carries
 * the same identity stamp it had when captured.
 *
 * Layered with objpool_check(): that gate filters out obviously-wild
 * pointers and cross-pool reads via the VA-range + obj_type checks,
 * but cannot tell a stale "same address, same type, recycled identity"
 * obj from a fresh one.  This check closes that remaining window.
 *
 * The zero left in obj->slot_version by release_obj()'s memset is a
 * reserved sentinel: add_object() never issues 0, so a captured
 * version > 0 compared against 0 always fails and a stale read off a
 * freed chunk returns false without further work.
 */
static inline bool object_slot_alive(const struct object *obj,
				     unsigned int captured_version)
{
	if (obj == NULL)
		return false;
	return obj->slot_version == captured_version;
}

bool objects_empty(enum objecttype type);
bool objects_pool_empty(enum obj_scope scope, enum objecttype type);
struct objhead * get_objhead(enum obj_scope scope, enum objecttype type) __must_check;
void prune_objects(void);
int fd_from_object(struct object *obj, enum objecttype type);
void set_object_fd(struct object *obj, enum objecttype type, int fd);

/*
 * Generic objhead->destroy handler for fd-bearing pools whose teardown
 * is nothing more than close() on the per-pool fd.  Looks the fd up via
 * fd_from_object(obj, obj->obj_type), so providers that need extra
 * cleanup (mq_unlink, munmap of mapped rings, peer fixups, freeing a
 * shared name buffer, ...) must keep their bespoke destructor instead
 * of registering this one.
 */
void close_fd_destructor(struct object *obj);

/*
 * Generic objhead->dump handler for fd-bearing pools whose dump line is
 * the canonical "<name> fd:<n> scope:<s>" form with no extra fields.
 * The per-objtype label is resolved internally; providers whose dump
 * carries extra state (filename, flags, paired-fd, ...) must keep their
 * bespoke dumper.
 */
void generic_fd_dump(struct object *obj, enum obj_scope scope);
struct object *find_local_object_by_fd(enum objecttype type, int fd);

/*
 * Walk every OBJ_LOCAL fd-typed pool for the calling child and return
 * the object that owns @fd, or NULL if no local pool tracks it.  Lets
 * fd_lookup_provider reach fds that live only in per-child OBJ_LOCAL
 * pools (kvm-vcpu, kvm-vm, io_uring, userfaultfd, pidfd,
 * seccomp-notif, ...) — those never enter the fork-time global
 * fd_hash snapshot, so the epoll/poll/select sanitisers rely on this
 * lookup to register them in watch sets (blocking ->poll handlers need
 * the fd visible).
 */
struct object *local_fd_find_by_fd(int fd);

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
/*
 * Remove an entry from THIS child's snapshot of fd_hash[].  Safe to
 * call from child context only; in the parent or before
 * this_child() is initialised it is a no-op.  Use alongside
 * fd_event_enqueue(FD_EVENT_CLOSE) so the closing child stops
 * handing out the just-closed fd from get_random_fd() /
 * get_typed_fd() before the parent drains the event.  Most
 * child-side close paths should call notify_child_fd_closed()
 * instead, which bundles this with the matching event-enqueue and
 * live-fd-ring eviction so all three steps stay in lockstep.
 */
void fd_hash_remove_local(int fd);
/*
 * Range variant of fd_hash_remove_local: evict every fd in [lo, hi]
 * from THIS child's fd_hash[] snapshot.  Same context rules as
 * fd_hash_remove_local -- child only, parent and pre-init are
 * no-ops.  Backs notify_child_fd_closed_range() for close_range()-
 * style bulk closes.
 */
void fd_hash_remove_local_range(int lo, int hi);
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
