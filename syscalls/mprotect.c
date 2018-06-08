/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

static struct map* map;

static void sanitise_mprotect(__unused__ struct syscallrecord *rec)
{
	map = common_set_mmap_ptr_len();
}

/*
 * If we successfully did an mprotect, update our record of the mappings prot bits.
 */
static void post_mprotect(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		map->prot = rec->a3;
}

static unsigned long mprotect_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
	PROT_GROWSDOWN, PROT_GROWSUP,
};

struct syscallentry syscall_mprotect = {
	.name = "mprotect",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(mprotect_prots),
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};

struct syscallentry syscall_pkey_mprotect = {
	.name = "pkey_mprotect",
	.num_args = 4,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(mprotect_prots),
	.arg4name = "key",
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};
