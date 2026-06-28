/*
 * SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len)
 */
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

#define SYSLOG_ACTION_CLOSE          0
#define SYSLOG_ACTION_OPEN           1
#define SYSLOG_ACTION_READ           2
#define SYSLOG_ACTION_READ_ALL       3
#define SYSLOG_ACTION_READ_CLEAR     4
#define SYSLOG_ACTION_CLEAR          5
#define SYSLOG_ACTION_CONSOLE_OFF    6
#define SYSLOG_ACTION_CONSOLE_ON     7
#define SYSLOG_ACTION_CONSOLE_LEVEL  8
#define SYSLOG_ACTION_SIZE_UNREAD    9
#define SYSLOG_ACTION_SIZE_BUFFER   10

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

		map = get_map();
		if (map == NULL) {
			rec->a2 = 0;
			rec->a3 = 0;
			return;
		}

		rec->a2 = (unsigned long) map->ptr;

		len_pick = rnd_modulo_u32(100);
		if (len_pick < 20)
			rec->a3 = 0;
		else if (len_pick < 35)
			rec->a3 = 1;
		else if (len_pick < 50)
			rec->a3 = rnd_modulo_u32(64);
		else if (len_pick < 70)
			rec->a3 = map->size;
		else if (len_pick < 85)
			rec->a3 = rnd_modulo_u32(map->size) & PAGE_MASK;
		else if (len_pick < 95)
			rec->a3 = map->size + page_size;
		else
			rec->a3 = 0x80000000UL;

		avoid_shared_buffer_out(&rec->a2, rec->a3);
		return;
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
		return;
	}

	if (class == CLASS_VOID || class == CLASS_SIZE) {
		if (rnd_modulo_u32(5) == 0) {
			struct map *map = get_map();

			if (map != NULL) {
				rec->a2 = (unsigned long) map->ptr;
				rec->a3 = rnd_modulo_u32(map->size);
				avoid_shared_buffer_out(&rec->a2, rec->a3);
				return;
			}
		}
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	if (class == CLASS_INVALID) {
		struct map *map = get_map();

		rec->a2 = map ? (unsigned long) map->ptr : 0;
		rec->a3 = rnd_modulo_u32(page_size);
		return;
	}

	/* CLASS_RANDOM: keep the pre-existing page-aligned shape so
	 * the baseline coverage path is preserved unchanged. */
	{
		struct map *map = get_map();

		if (map == NULL) {
			rec->a2 = 0;
			rec->a3 = 0;
			return;
		}

		rec->a2 = (unsigned long) map->ptr;
		rec->a3 = rnd_modulo_u32(map->size) & PAGE_MASK;
		avoid_shared_buffer_out(&rec->a2, rec->a3);
	}
}

struct syscallentry syscall_syslog = {
	.name = "syslog",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_MMAP, [2] = ARG_LEN },
	.argname = { [0] = "type", [1] = "buf", [2] = "len" },
	.arg_params[0].list = ARGLIST(syslog_types),
	.sanitise = sanitise_syslog,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
