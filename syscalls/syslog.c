/*
 * SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len)
 *
 * The final len of a read action stays inside the buffer the sanitiser
 * sized, buf included (vet_final_syslog()).
 */
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/syslog.h"

/*
 * Per-cmd-class buffer shaping.  do_syslog() in the kernel splits
 * its 11 SYSLOG_ACTION_* commands into three disjoint argument
 * shapes plus an invalid bucket:
 *
 *   READ-class {2,3,4}            copy a byte count of log into buf
 *   CONSOLE_LEVEL {8}             treats `len` as a level 1..8;
 *                                 buf is ignored
 *   VOID-arg {0,1,5,6,7,9,10}     both buf and len are ignored
 *   invalid {-1, 11, 12, ...}     leading switch rejects with -EINVAL
 *
 * ARG_OP fills rec->a1 from syslog_types[] before sanitise runs;
 * we override it here so we can shape (a2, a3) to match the chosen
 * cmd class.  The read-class arm is the only one that needs a map;
 * the others skip get_map() entirely so the limited map pool is
 * spent on calls that can actually exercise the copy_to_user path.
 */
static unsigned long syslog_types[] = {
	SYSLOG_ACTION_CLOSE,
	SYSLOG_ACTION_OPEN,
	SYSLOG_ACTION_READ,
	SYSLOG_ACTION_READ_CLEAR,
	SYSLOG_ACTION_READ_ALL,
	SYSLOG_ACTION_CLEAR,
	SYSLOG_ACTION_CONSOLE_OFF,
	SYSLOG_ACTION_CONSOLE_ON,
	SYSLOG_ACTION_CONSOLE_LEVEL,
	SYSLOG_ACTION_SIZE_UNREAD,
	SYSLOG_ACTION_SIZE_BUFFER,
};

/*
 * The buffer attach_buffer() aimed at the picked mapping, and how many
 * bytes from it the kernel may write: the mapping's walkable size, or the
 * length the pool slot the buffer moved to was sized for.  Captured at
 * sanitise time for the final-slot hook, which has nothing else to name
 * the buffer by: a slot rewritten after the sanitiser holds whatever the
 * rewrite put there.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose.
 */
#define SYSLOG_POST_STATE_MAGIC	0x5359534C4F475F50UL	/* "SYSLOG_P" */
struct syslog_post_state {
	unsigned long magic;
	unsigned long buf;
	size_t extent;
};

/*
 * do_syslog() copies up to len bytes of log into buf for the three read
 * actions and writes nothing through buf for any other, so only a read is
 * held here.  The type is ARG_OP, which chain substitution may rewrite,
 * and a RedQueen pin may rewrite any slot: either can turn a call the
 * sanitiser built for another action, one with a buffer it never vetted
 * included, into a read, or grow the len of one it did.  A read has to
 * name the buffer the sanitiser recorded and fit the extent it recorded
 * for it.  The kernel reads type and len as ints, buf as a pointer (the
 * low 32 bits for a compat call).  A len of 0 or below copies nothing, a
 * negative one being refused before anything is, and a NULL buf takes no
 * copy; a record with no snapshot of ours passes only those.  Refused
 * rather than repaired, each slot read once.  Shape, then ownership, then
 * magic, as post_state_claim_owned() orders them.
 */
static int vet_final_syslog(struct syscallrecord *rec,
			    const struct syscallentry *entry)
{
	struct syslog_post_state *snap =
		(struct syslog_post_state *) rec->post_state;
	int type = (int) rec->a1, len = (int) rec->a3;
	unsigned long buf = rec->do32bit ? (unsigned int) rec->a2 : rec->a2;
	size_t extent = 0;

	if (type != SYSLOG_ACTION_READ && type != SYSLOG_ACTION_READ_ALL &&
	    type != SYSLOG_ACTION_READ_CLEAR)
		return 0;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == SYSLOG_POST_STATE_MAGIC)
		extent = snap->extent;
	else
		snap = NULL;

	/* A len left after the first test fits extent, so snap is ours. */
	if (buf != 0 && len > 0 && ((size_t) len > extent || buf != snap->buf)) {
		outputerr("arg-coupling: %s rejected: the len runs past the buffer sanitise sized, or buf is not the one it sized\n",
			  entry->name);
		return -1;
	}
	return 0;
}

/*
 * Aim the buffer at @map for a call of @len bytes, off trinity's regions,
 * and record what the final-slot hook holds the call to.
 */
static void attach_buffer(struct syscallrecord *rec, struct map *map,
			  unsigned long len)
{
	struct syslog_post_state *snap = zmalloc_tracked(sizeof(*snap));

	rec->a2 = (unsigned long) map->ptr;
	rec->a3 = len;
	avoid_shared_buffer_out(&rec->a2, rec->a3);

	/* A compat call's kernel reads the low 32 bits of the buffer slot,
	 * which for a buffer above them is an address nobody sized: it has
	 * no bytes to copy into it. */
	if (rec->do32bit && rec->a2 > UINT_MAX)
		rec->a3 = 0;

	snap->magic = SYSLOG_POST_STATE_MAGIC;
	snap->buf = rec->a2;
	snap->extent = rec->a2 == (unsigned long) map->ptr ? map->size : rec->a3;
	post_state_install(rec, snap);
}

static void sanitise_syslog(struct syscallrecord *rec)
{
	static const unsigned long read_cmds[] = {
		SYSLOG_ACTION_READ,
		SYSLOG_ACTION_READ_ALL,
		SYSLOG_ACTION_READ_CLEAR,
	};
	static const unsigned long void_cmds[] = {
		SYSLOG_ACTION_CLOSE,
		SYSLOG_ACTION_OPEN,
		SYSLOG_ACTION_CLEAR,
		SYSLOG_ACTION_CONSOLE_OFF,
		SYSLOG_ACTION_CONSOLE_ON,
	};
	static const unsigned long invalid_cmds[] = {
		(unsigned long) -1L,
		11,
		12,
		0x80000000UL,
	};
	unsigned int pick = rnd_modulo_u32(100);
	enum { CLASS_READ, CLASS_LEVEL, CLASS_SIZE,
	       CLASS_VOID, CLASS_RANDOM, CLASS_INVALID } class;

	/*
	 * Clear post_state up front so a class that attaches no buffer
	 * leaves the final-slot hook and the cleanup with no snapshot rather
	 * than a stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

	if (pick < 35)
		class = CLASS_READ;
	else if (pick < 45)
		class = CLASS_LEVEL;
	else if (pick < 55)
		class = CLASS_SIZE;
	else if (pick < 85)
		class = CLASS_VOID;
	else if (pick < 95)
		class = CLASS_RANDOM;
	else
		class = CLASS_INVALID;

	switch (class) {
	case CLASS_READ:
		rec->a1 = read_cmds[rnd_modulo_u32(ARRAY_SIZE(read_cmds))];
		break;
	case CLASS_LEVEL:
		rec->a1 = SYSLOG_ACTION_CONSOLE_LEVEL;
		break;
	case CLASS_SIZE:
		rec->a1 = (rnd_modulo_u32(2) == 0)
			? SYSLOG_ACTION_SIZE_UNREAD
			: SYSLOG_ACTION_SIZE_BUFFER;
		break;
	case CLASS_VOID:
		rec->a1 = void_cmds[rnd_modulo_u32(ARRAY_SIZE(void_cmds))];
		break;
	case CLASS_INVALID:
		rec->a1 = invalid_cmds[rnd_modulo_u32(ARRAY_SIZE(invalid_cmds))];
		break;
	case CLASS_RANDOM:
		rec->a1 = syslog_types[rnd_modulo_u32(ARRAY_SIZE(syslog_types))];
		break;
	}

	if (class == CLASS_READ) {
		struct map *map;
		unsigned int len_pick;
		unsigned long len;

		map = get_map();
		if (map == NULL) {
			rec->a2 = 0;
			rec->a3 = 0;
			goto out;
		}

		len_pick = rnd_modulo_u32(100);
		if (len_pick < 20)
			len = 0;
		else if (len_pick < 35)
			len = 1;
		else if (len_pick < 50)
			len = rnd_modulo_u32(64);
		else if (len_pick < 70)
			len = map->size;
		else if (len_pick < 95)
			len = rnd_modulo_u32(map->size) & PAGE_MASK;
		else
			len = 0x80000000UL;

		attach_buffer(rec, map, len);
		goto out;
	}

	if (class == CLASS_LEVEL) {
		unsigned int p = rnd_modulo_u32(100);

		rec->a2 = 0;
		if (p < 70)
			rec->a3 = RAND_RANGE(1, 8);
		else if (p < 80)
			rec->a3 = 0;
		else if (p < 90)
			rec->a3 = 9;
		else
			rec->a3 = rnd_u32();
		goto out;
	}

	if (class == CLASS_VOID || class == CLASS_SIZE) {
		if (rnd_modulo_u32(5) == 0) {
			struct map *map = get_map();

			if (map != NULL) {
				attach_buffer(rec, map, rnd_modulo_u32(map->size));
				goto out;
			}
		}
		rec->a2 = 0;
		rec->a3 = 0;
		goto out;
	}

	if (class == CLASS_INVALID) {
		struct map *map = get_map();

		rec->a2 = map ? (unsigned long) map->ptr : 0;
		rec->a3 = rnd_modulo_u32(page_size);
		goto out;
	}

	/* CLASS_RANDOM: keep the pre-existing page-aligned shape so
	 * the baseline coverage path is preserved unchanged. */
	{
		struct map *map = get_map();

		if (map == NULL) {
			rec->a2 = 0;
			rec->a3 = 0;
			goto out;
		}

		attach_buffer(rec, map, rnd_modulo_u32(map->size) & PAGE_MASK);
	}

out:
	/* Light REEXEC_OK when no user buffer was attached — CLASS_LEVEL always,
	 * VOID/SIZE on their no-buffer path.  Excludes READ/RANDOM/INVALID and
	 * any VOID/SIZE arm that attached a mmap buffer (rec->a2 != 0). */
	if (rec->a2 == 0)
		rec->flags |= REEXEC_OK;
}

/* The snapshot is the final-slot hook's alone, so it goes on every path. */
static void cleanup_syslog(struct syscallrecord *rec)
{
	struct syslog_post_state *snap;

	snap = post_state_claim_owned(rec, SYSLOG_POST_STATE_MAGIC, __func__);
	post_state_release(rec, snap);
}

struct syscallentry syscall_syslog = {
	.name = "syslog",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_MMAP, [2] = ARG_LEN },
	.argname = { [0] = "type", [1] = "buf", [2] = "len" },
	.arg_params[0].list = ARGLIST(syslog_types),
	.sanitise = sanitise_syslog,
	.vet_final = vet_final_syslog,
	.cleanup = cleanup_syslog,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT | REEXEC_SANITISE_OK,
	.rettype = RET_BORING,
};
