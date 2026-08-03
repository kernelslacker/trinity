/*
 * Observation-only resource type-graph.
 *
 * See include/type-graph.h for the rationale and the on-shm shape.
 * This file owns the direct-mapped publish ring, the open-addressed
 * edge pool, the EMA update primitive, and the top-N text and JSON
 * dumps.  Nothing here reads back into the picker in random_syscall/
 * -- Slice A is observation only; a byte-identical fuzzing run with
 * the observer wired is the design contract.
 *
 * Cross-child concurrency: the publish ring uses a single monotonic
 * generation stamp under RELAXED atomics; the edge pool uses a CAS
 * on the primary key to publish an insert and RELAXED atomic RMWs on
 * the EMA counters.  A lost-race duplicate insert is possible in a
 * narrow window and would surface as a second edge with the same
 * primary key -- acceptable at the observability grain of Slice A.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "child-api.h"
#include "child.h"
#include "object-types.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "type-graph.h"
#include "utils.h"
#include "utils-mem.h"

struct type_graph_shm *type_graph_shm = NULL;

/*
 * Per-child pending handoff: chain-subst records the (producer,
 * consumer, obj_type, slot) tuple here and the chain executor's
 * post-dispatch outcome hook commits it into the edge pool.  Kept
 * as file-scope static because children are separate processes; a
 * per-child copy comes for free via COW at fork.
 */
static struct {
	bool valid;
	uint16_t producer_nr;
	uint16_t consumer_nr;
	uint8_t obj_type;
	uint8_t consumer_arg;
	uint8_t producer_do32;
	uint8_t consumer_do32;
} pending_edge;

/* EMA scaling: each observation credits EMA_INCREMENT and the
 * one-step decay is old - old/EMA_DECAY_SHIFT.  Steady-state for a
 * counter that fires every observation is EMA_INCREMENT << EMA_DECAY_
 * SHIFT, i.e. 100 << 6 == 6400 -- fits in uint32 with headroom. */
#define EMA_DECAY_SHIFT		6u
#define EMA_INCREMENT		100u

/*
 * Slot index derives from (owner, id) not id alone.  Kernel handles
 * are per-child namespaces: fd 5 in child A and fd 5 in child B are
 * unrelated objects that would otherwise collide on the same ring
 * slot and cross-attribute producer records.  Mixing the owner num
 * into the hash spreads siblings' publishes across the ring; the
 * consume side still compares owner in the slot to catch the
 * residual same-bucket collisions.
 */
static uint32_t hash_id(unsigned int owner, unsigned long id)
{
	uint32_t x = (uint32_t)id ^ (uint32_t)(id >> 32) ^ owner;

	x ^= x >> 16;
	x *= 0x85ebca6bu;
	x ^= x >> 13;
	x *= 0xc2b2ae35u;
	x ^= x >> 16;
	return x;
}

static uint32_t hash_edge(uint16_t producer_nr, uint16_t consumer_nr,
			  uint8_t obj_type, uint8_t consumer_arg)
{
	uint32_t x = ((uint32_t)producer_nr << 16) | (uint32_t)consumer_nr;

	x ^= ((uint32_t)obj_type << 8) | (uint32_t)consumer_arg;
	x *= 0x9e3779b1u;
	x ^= x >> 16;
	return x;
}

static uint32_t edge_key(uint16_t producer_nr, uint16_t consumer_nr)
{
	/*
	 * +1 encoding so the empty-slot sentinel (key == 0) stays
	 * distinct from a legitimate producer_nr / consumer_nr == 0
	 * pairing.  Both nrs fit in 15 bits after +1 (MAX_NR_SYSCALL
	 * is 1024) so the shifted layout has no overlap.
	 */
	uint32_t p = (uint32_t)producer_nr + 1u;
	uint32_t c = (uint32_t)consumer_nr + 1u;

	return (p << 16) | c;
}

static uint32_t edge_sub_key(uint8_t obj_type, uint8_t consumer_arg)
{
	return ((uint32_t)obj_type << 8) | (uint32_t)consumer_arg;
}

static void ema_bump(uint32_t *cell, uint32_t inc)
{
	uint32_t old = __atomic_load_n(cell, __ATOMIC_RELAXED);
	uint32_t new_val;

	do {
		new_val = old - (old >> EMA_DECAY_SHIFT) + inc;
	} while (!__atomic_compare_exchange_n(cell, &old, new_val,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));
}

void type_graph_init(void)
{
	type_graph_shm = alloc_shared_pool(sizeof(struct type_graph_shm));
	memset(type_graph_shm, 0, sizeof(struct type_graph_shm));
	output(0, "type-graph: allocated %u publish slots, %u edge slots (%lu B)\n",
	       TYPE_GRAPH_PUBLISH_SLOTS, TYPE_GRAPH_EDGES_MAX,
	       (unsigned long)sizeof(struct type_graph_shm));
}

void type_graph_observe_publish(unsigned int producer_nr, bool do32bit,
				enum objecttype type, unsigned long id)
{
	struct type_graph_publish_slot *slot;
	struct childdata *child;
	uint32_t owner;
	uint32_t gen;

	if (type_graph_shm == NULL)
		return;
	if (producer_nr >= MAX_NR_SYSCALL)
		return;
	if (type == OBJ_NONE || (unsigned int)type >= MAX_OBJECT_TYPES)
		return;

	child = this_child();
	if (child == NULL)
		return;
	owner = (uint32_t)child->num;

	gen = __atomic_add_fetch(&type_graph_shm->next_gen, 1u,
				 __ATOMIC_RELAXED);
	if (gen == 0u)
		gen = __atomic_add_fetch(&type_graph_shm->next_gen, 1u,
					 __ATOMIC_RELAXED);

	slot = &type_graph_shm->publish[hash_id(owner, id) &
					(TYPE_GRAPH_PUBLISH_SLOTS - 1u)];
	__atomic_store_n(&slot->id, id, __ATOMIC_RELAXED);
	__atomic_store_n(&slot->owner, owner, __ATOMIC_RELAXED);
	__atomic_store_n(&slot->producer_nr, (uint16_t)producer_nr,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&slot->obj_type, (uint8_t)type, __ATOMIC_RELAXED);
	__atomic_store_n(&slot->producer_do32, (uint8_t)(do32bit ? 1 : 0),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&slot->gen, gen, __ATOMIC_RELEASE);

	__atomic_add_fetch(&type_graph_shm->publish_observations, 1UL,
			   __ATOMIC_RELAXED);
}

void type_graph_observe_consume(unsigned int consumer_nr, bool do32bit,
				unsigned int consumer_arg,
				unsigned long substitute_retval)
{
	struct type_graph_publish_slot *slot;
	struct childdata *child;
	uint32_t owner;
	uint32_t slot_owner;
	uint32_t gen;
	unsigned long id;
	uint16_t producer_nr;
	uint8_t obj_type;
	uint8_t producer_do32;

	pending_edge.valid = false;

	if (type_graph_shm == NULL)
		return;
	if (consumer_nr >= MAX_NR_SYSCALL)
		return;
	if (consumer_arg == 0u || consumer_arg > 6u)
		return;

	child = this_child();
	if (child == NULL)
		return;
	owner = (uint32_t)child->num;

	__atomic_add_fetch(&type_graph_shm->consume_observations, 1UL,
			   __ATOMIC_RELAXED);

	slot = &type_graph_shm->publish[hash_id(owner, substitute_retval) &
					(TYPE_GRAPH_PUBLISH_SLOTS - 1u)];
	gen = __atomic_load_n(&slot->gen, __ATOMIC_ACQUIRE);
	if (gen == 0u) {
		__atomic_add_fetch(&type_graph_shm->consume_misses, 1UL,
				   __ATOMIC_RELAXED);
		return;
	}

	id = __atomic_load_n(&slot->id, __ATOMIC_RELAXED);
	if (id != substitute_retval) {
		__atomic_add_fetch(&type_graph_shm->consume_misses, 1UL,
				   __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Owner match is what makes the whole thing sound: even with
	 * owner mixed into the hash, two children can land in the same
	 * bucket for different ids that happen to hash together, and a
	 * fresh publish from a sibling can overwrite our slot between
	 * our own publish and consume.  Reject anything that isn't
	 * stamped with our own child->num.
	 */
	slot_owner = __atomic_load_n(&slot->owner, __ATOMIC_RELAXED);
	if (slot_owner != owner) {
		__atomic_add_fetch(&type_graph_shm->consume_misses, 1UL,
				   __ATOMIC_RELAXED);
		return;
	}

	producer_nr = __atomic_load_n(&slot->producer_nr, __ATOMIC_RELAXED);
	obj_type = __atomic_load_n(&slot->obj_type, __ATOMIC_RELAXED);
	producer_do32 = __atomic_load_n(&slot->producer_do32,
					__ATOMIC_RELAXED);

	pending_edge.valid = true;
	pending_edge.producer_nr = producer_nr;
	pending_edge.consumer_nr = (uint16_t)consumer_nr;
	pending_edge.obj_type = obj_type;
	pending_edge.consumer_arg = (uint8_t)consumer_arg;
	pending_edge.producer_do32 = producer_do32;
	pending_edge.consumer_do32 = (uint8_t)(do32bit ? 1 : 0);

	__atomic_add_fetch(&type_graph_shm->consume_hits, 1UL,
			   __ATOMIC_RELAXED);
}

/*
 * Locate the edge slot for (p, c, t, a), inserting into an empty
 * slot within TYPE_GRAPH_EDGE_PROBES linear probes if none exists
 * yet.  Returns NULL when every candidate slot belongs to a
 * different edge -- caller bumps edge_pool_exhausted.
 */
static struct type_graph_edge *edge_lookup_or_insert(uint16_t producer_nr,
						     uint16_t consumer_nr,
						     uint8_t obj_type,
						     uint8_t consumer_arg,
						     uint8_t producer_do32,
						     uint8_t consumer_do32)
{
	uint32_t want_key = edge_key(producer_nr, consumer_nr);
	uint32_t want_sub = edge_sub_key(obj_type, consumer_arg);
	uint32_t h = hash_edge(producer_nr, consumer_nr, obj_type, consumer_arg);
	unsigned int i;

	for (i = 0; i < TYPE_GRAPH_EDGE_PROBES; i++) {
		struct type_graph_edge *e;
		uint32_t seen_key;
		uint32_t seen_sub;

		e = &type_graph_shm->edges[(h + i) & (TYPE_GRAPH_EDGES_MAX - 1u)];

		seen_key = __atomic_load_n(&e->key, __ATOMIC_ACQUIRE);
		if (seen_key == want_key) {
			seen_sub = __atomic_load_n(&e->sub_key,
						   __ATOMIC_ACQUIRE);
			if (seen_sub == want_sub)
				return e;
			continue;
		}
		if (seen_key != 0u)
			continue;

		/*
		 * Empty slot; try to claim.  A lost CAS either lost to
		 * another writer inserting our exact edge (re-check keys
		 * and use the slot) or to a writer inserting a different
		 * edge (fall through and continue probing).
		 */
		if (__atomic_compare_exchange_n(&e->key, &seen_key, want_key,
						false,
						__ATOMIC_ACQ_REL,
						__ATOMIC_ACQUIRE)) {
			e->producer_do32 = producer_do32;
			e->consumer_do32 = consumer_do32;
			__atomic_store_n(&e->sub_key, want_sub,
					 __ATOMIC_RELEASE);
			__atomic_add_fetch(&type_graph_shm->edge_inserts,
					   1UL, __ATOMIC_RELAXED);
			return e;
		}

		if (seen_key == want_key) {
			seen_sub = __atomic_load_n(&e->sub_key,
						   __ATOMIC_ACQUIRE);
			if (seen_sub == want_sub)
				return e;
		}
		continue;
	}

	return NULL;
}

void type_graph_commit_outcome(bool success, bool novel)
{
	struct type_graph_edge *e;

	if (!pending_edge.valid)
		return;
	pending_edge.valid = false;

	if (type_graph_shm == NULL)
		return;

	e = edge_lookup_or_insert(pending_edge.producer_nr,
				  pending_edge.consumer_nr,
				  pending_edge.obj_type,
				  pending_edge.consumer_arg,
				  pending_edge.producer_do32,
				  pending_edge.consumer_do32);
	if (e == NULL) {
		__atomic_add_fetch(&type_graph_shm->edge_pool_exhausted,
				   1UL, __ATOMIC_RELAXED);
		return;
	}

	ema_bump(&e->total_ema, EMA_INCREMENT);
	if (success)
		ema_bump(&e->success_ema, EMA_INCREMENT);
	if (novel)
		ema_bump(&e->novel_ema, EMA_INCREMENT);
	__atomic_add_fetch(&e->observations, 1UL, __ATOMIC_RELAXED);
	__atomic_add_fetch(&type_graph_shm->edge_updates, 1UL,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&type_graph_shm->outcome_commits, 1UL,
			   __ATOMIC_RELAXED);
}

/*
 * Object-type printable name.  Kept ASCII and short so the text
 * dump and JSON output stay parseable without escaping.  Any type
 * added to enum objecttype after this table falls into the default
 * "OBJ_?" formatter -- a downstream operator sees the numeric type
 * and files a follow-up rather than getting a truncated dump.
 */
const char *type_graph_obj_type_name(uint8_t type)
{
	switch ((enum objecttype)type) {
	case OBJ_NONE:			return "NONE";
	case OBJ_MMAP_ANON:		return "MMAP_ANON";
	case OBJ_MMAP_FILE:		return "MMAP_FILE";
	case OBJ_MMAP_TESTFILE:		return "MMAP_TESTFILE";
	case OBJ_FD_PIPE:		return "FD_PIPE";
	case OBJ_FD_DEVFILE:		return "FD_DEVFILE";
	case OBJ_FD_DEV_TEMPLATE:	return "FD_DEV_TEMPLATE";
	case OBJ_FD_PROCFILE:		return "FD_PROCFILE";
	case OBJ_FD_SYSFILE:		return "FD_SYSFILE";
	case OBJ_FD_PERF:		return "FD_PERF";
	case OBJ_FD_EPOLL:		return "FD_EPOLL";
	case OBJ_FD_EVENTFD:		return "FD_EVENTFD";
	case OBJ_FD_TIMERFD:		return "FD_TIMERFD";
	case OBJ_FD_TESTFILE:		return "FD_TESTFILE";
	case OBJ_FD_MEMFD:		return "FD_MEMFD";
	case OBJ_FD_MEMFD_SECRET:	return "FD_MEMFD_SECRET";
	case OBJ_FD_DRM:		return "FD_DRM";
	case OBJ_FD_INOTIFY:		return "FD_INOTIFY";
	case OBJ_FD_SOCKET:		return "FD_SOCKET";
	case OBJ_FD_USERFAULTFD:	return "FD_USERFAULTFD";
	case OBJ_FD_FANOTIFY:		return "FD_FANOTIFY";
	case OBJ_FD_BPF_MAP:		return "FD_BPF_MAP";
	case OBJ_FD_BPF_PROG:		return "FD_BPF_PROG";
	case OBJ_FD_BPF_LINK:		return "FD_BPF_LINK";
	case OBJ_FD_BPF_BTF:		return "FD_BPF_BTF";
	case OBJ_FD_BPF_TOKEN:		return "FD_BPF_TOKEN";
	case OBJ_FD_IO_URING:		return "FD_IO_URING";
	case OBJ_FD_LANDLOCK:		return "FD_LANDLOCK";
	case OBJ_FD_PIDFD:		return "FD_PIDFD";
	case OBJ_FD_MQ:			return "FD_MQ";
	case OBJ_FD_SPARSE_FILE:	return "FD_SPARSE_FILE";
	case OBJ_FD_SECCOMP_NOTIF:	return "FD_SECCOMP_NOTIF";
	case OBJ_FD_IOMMUFD:		return "FD_IOMMUFD";
	case OBJ_FD_FS_CTX:		return "FD_FS_CTX";
	case OBJ_FD_KVM_SYSTEM:		return "FD_KVM_SYSTEM";
	case OBJ_FD_KVM_VM:		return "FD_KVM_VM";
	case OBJ_FD_KVM_VCPU:		return "FD_KVM_VCPU";
	case OBJ_FD_PAGECACHE:		return "FD_PAGECACHE";
	case OBJ_FD_WRITEABLE_PAGECACHE: return "FD_WRITEABLE_PAGECACHE";
	case OBJ_FD_CANARY:		return "FD_CANARY";
	case OBJ_FD_SIGNALFD:		return "FD_SIGNALFD";
	case OBJ_FD_MOUNT:		return "FD_MOUNT";
	case OBJ_FD_CGROUP:		return "FD_CGROUP";
	case OBJ_FD_WATCH_QUEUE:	return "FD_WATCH_QUEUE";
	case OBJ_FD_SCRATCH_BLOCK:	return "FD_SCRATCH_BLOCK";
	case OBJ_AIO_CTX:		return "AIO_CTX";
	case OBJ_AIO_IOCB:		return "AIO_IOCB";
	case OBJ_KEY_SERIAL:		return "KEY_SERIAL";
	case OBJ_PKEY:			return "PKEY";
	case OBJ_TIMERID:		return "TIMERID";
	case OBJ_PID:			return "PID";
	case OBJ_FUTEX:			return "FUTEX";
	case OBJ_FUTEX_SHARED:		return "FUTEX_SHARED";
	case OBJ_SYSV_SHM:		return "SYSV_SHM";
	case OBJ_SYSV_SEM:		return "SYSV_SEM";
	case OBJ_SYSV_MSG:		return "SYSV_MSG";
	case MAX_OBJECT_TYPES:		break;
	}
	return NULL;
}

const char *type_graph_syscall_name(uint16_t nr, uint8_t do32bit)
{
	struct syscallentry *entry;

	entry = get_syscall_entry(nr, do32bit ? true : false);
	if (entry == NULL)
		return NULL;
	return entry->name;
}

struct top_slot {
	const struct type_graph_edge *e;
	uint32_t total;
};

/*
 * Insert-sort into a fixed-size top-N array indexed by total_ema.
 * Callers pre-zero the vector; count tracks live entries so the
 * dump helpers can stop early when the observer is quiet.
 */
static void top_push(struct top_slot *top, unsigned int cap,
		     unsigned int *count,
		     const struct type_graph_edge *e, uint32_t total)
{
	unsigned int i;
	unsigned int pos;

	if (total == 0u)
		return;
	if (*count < cap) {
		pos = *count;
		(*count)++;
	} else {
		pos = cap;
		for (i = 0; i < cap; i++) {
			if (top[i].total < total &&
			    (pos == cap || top[i].total < top[pos].total))
				pos = i;
		}
		if (pos == cap)
			return;
	}
	top[pos].e = e;
	top[pos].total = total;

	for (i = pos; i > 0; i--) {
		if (top[i].total <= top[i - 1].total)
			break;
		{
			struct top_slot tmp = top[i];

			top[i] = top[i - 1];
			top[i - 1] = tmp;
		}
	}
}

static unsigned int gather_top(struct top_slot *top)
{
	unsigned int i;
	unsigned int count = 0;

	for (i = 0; i < TYPE_GRAPH_EDGES_MAX; i++) {
		const struct type_graph_edge *e = &type_graph_shm->edges[i];
		uint32_t key = __atomic_load_n(&e->key, __ATOMIC_ACQUIRE);
		uint32_t total;

		if (key == 0u)
			continue;
		total = __atomic_load_n(&e->total_ema, __ATOMIC_RELAXED);
		top_push(top, TYPE_GRAPH_TOP_N, &count, e, total);
	}
	return count;
}

void type_graph_dump_top_handoffs(void)
{
	struct top_slot top[TYPE_GRAPH_TOP_N];
	unsigned int count;
	unsigned int i;
	uint64_t publish_obs;
	uint64_t consume_obs;
	uint64_t consume_hits;
	uint64_t consume_misses;
	uint64_t edge_inserts;
	uint64_t edge_updates;
	uint64_t exhausted;

	if (type_graph_shm == NULL)
		return;

	publish_obs = __atomic_load_n(&type_graph_shm->publish_observations,
				      __ATOMIC_RELAXED);
	consume_obs = __atomic_load_n(&type_graph_shm->consume_observations,
				      __ATOMIC_RELAXED);
	consume_hits = __atomic_load_n(&type_graph_shm->consume_hits,
				       __ATOMIC_RELAXED);
	consume_misses = __atomic_load_n(&type_graph_shm->consume_misses,
					 __ATOMIC_RELAXED);
	edge_inserts = __atomic_load_n(&type_graph_shm->edge_inserts,
				       __ATOMIC_RELAXED);
	edge_updates = __atomic_load_n(&type_graph_shm->edge_updates,
				       __ATOMIC_RELAXED);
	exhausted = __atomic_load_n(&type_graph_shm->edge_pool_exhausted,
				    __ATOMIC_RELAXED);

	if (publish_obs == 0 && consume_obs == 0)
		return;

	output(0,
	       "type_graph: publish=%lu consume=%lu hits=%lu misses=%lu edges=%lu updates=%lu exhausted=%lu\n",
	       publish_obs, consume_obs, consume_hits, consume_misses,
	       edge_inserts, edge_updates, exhausted);

	memset(top, 0, sizeof(top));
	count = gather_top(top);
	if (count == 0)
		return;

	for (i = 0; i < count; i++) {
		const struct type_graph_edge *e = top[i].e;
		uint32_t key = __atomic_load_n(&e->key, __ATOMIC_RELAXED);
		uint32_t sub = __atomic_load_n(&e->sub_key, __ATOMIC_RELAXED);
		uint16_t producer_nr = (uint16_t)((key >> 16) - 1u);
		uint16_t consumer_nr = (uint16_t)((key & 0xffffu) - 1u);
		uint8_t obj_type = (uint8_t)(sub >> 8);
		uint8_t consumer_arg = (uint8_t)(sub & 0xffu);
		uint32_t total = top[i].total;
		uint32_t success = __atomic_load_n(&e->success_ema,
						   __ATOMIC_RELAXED);
		uint32_t novel = __atomic_load_n(&e->novel_ema,
						 __ATOMIC_RELAXED);
		uint64_t obs = __atomic_load_n(&e->observations,
					       __ATOMIC_RELAXED);
		const char *tname = type_graph_obj_type_name(obj_type);
		const char *pname = type_graph_syscall_name(producer_nr,
							    e->producer_do32);
		const char *cname = type_graph_syscall_name(consumer_nr,
							    e->consumer_do32);
		unsigned int win_ppk = total ? (unsigned int)(((uint64_t)success * 1000u) / total) : 0u;
		unsigned int nov_ppk = total ? (unsigned int)(((uint64_t)novel * 1000u) / total) : 0u;

		output(0,
		       "type_graph_top[%u]: %s -> %s arg=%u type=%s obs=%lu total_ema=%u win_permille=%u novel_permille=%u\n",
		       i, pname ? pname : "?",
		       cname ? cname : "?", consumer_arg,
		       tname ? tname : "OBJ_?",
		       obs, total, win_ppk, nov_ppk);
	}
}

unsigned int type_graph_get_top_handoffs(struct type_graph_top_entry *buf)
{
	struct top_slot top[TYPE_GRAPH_TOP_N];
	unsigned int count;
	unsigned int i;

	if (type_graph_shm == NULL)
		return 0;

	memset(top, 0, sizeof(top));
	count = gather_top(top);
	for (i = 0; i < count; i++) {
		const struct type_graph_edge *e = top[i].e;
		uint32_t key = __atomic_load_n(&e->key, __ATOMIC_RELAXED);
		uint32_t sub = __atomic_load_n(&e->sub_key, __ATOMIC_RELAXED);

		buf[i].producer_nr = (uint16_t)((key >> 16) - 1u);
		buf[i].consumer_nr = (uint16_t)((key & 0xffffu) - 1u);
		buf[i].obj_type = (uint8_t)(sub >> 8);
		buf[i].consumer_arg = (uint8_t)(sub & 0xffu);
		buf[i].producer_do32 = e->producer_do32;
		buf[i].consumer_do32 = e->consumer_do32;
		buf[i].total_ema = top[i].total;
		buf[i].success_ema = __atomic_load_n(&e->success_ema,
						     __ATOMIC_RELAXED);
		buf[i].novel_ema = __atomic_load_n(&e->novel_ema,
						   __ATOMIC_RELAXED);
		buf[i].observations = __atomic_load_n(&e->observations,
						      __ATOMIC_RELAXED);
	}
	return count;
}
