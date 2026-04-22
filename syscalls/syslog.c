/*
 * SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
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

static void sanitise_syslog(struct syscallrecord *rec)
{
	struct map *map;

	map = get_map();
	if (map == NULL) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	rec->a2 = (unsigned long) map->ptr;
	rec->a3 = rand() % map->size;
	rec->a3 &= PAGE_MASK;
	avoid_shared_buffer(&rec->a2, rec->a3);
}

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
