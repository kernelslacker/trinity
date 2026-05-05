/*
 * SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
	struct kexec_segment __user *, segments, unsigned long, flags)
 */

#include <linux/kexec.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

#ifndef KEXEC_UPDATE_ELFCOREHDR
#define KEXEC_UPDATE_ELFCOREHDR 0x00000004
#endif
#ifndef KEXEC_CRASH_HOTPLUG_SUPPORT
#define KEXEC_CRASH_HOTPLUG_SUPPORT 0x00000008
#endif

static unsigned long kexec_load_flags[] = {
	KEXEC_ON_CRASH, KEXEC_PRESERVE_CONTEXT,
	KEXEC_UPDATE_ELFCOREHDR, KEXEC_CRASH_HOTPLUG_SUPPORT,
};

/* Arch bits for flags[31:16] */
static unsigned long kexec_arches[] = {
	KEXEC_ARCH_DEFAULT, KEXEC_ARCH_386, KEXEC_ARCH_X86_64,
};

static void sanitise_kexec_load(struct syscallrecord *rec)
{
	struct kexec_segment *segs;
	unsigned int nr, i;
	unsigned long arch;

	/* 1-4 segments (KEXEC_SEGMENT_MAX is 16, keep it small) */
	nr = 1 + (rand() % 4);
	segs = (struct kexec_segment *) get_writable_address(nr * sizeof(*segs));
	memset(segs, 0, nr * sizeof(*segs));

	for (i = 0; i < nr; i++) {
		size_t sz = 4096 * (1 + (rand() % 4));	/* 4K-16K */
		void *buf;

		buf = get_writable_address(sz);
		memset(buf, 0, sz);

		segs[i].buf = buf;
		segs[i].bufsz = sz;
		/* mem/memsz: physical target — kernel validates these */
		segs[i].mem = (const void *)(unsigned long)(0x100000 + (i * 0x10000));
		segs[i].memsz = sz;
	}

	rec->a1 = 0;	/* entry point (kernel ignores for KEXEC_ON_CRASH) */
	rec->a2 = nr;
	rec->a3 = (unsigned long) segs;

	/* Combine low flags with arch in upper 16 bits */
	arch = kexec_arches[rand() % ARRAY_SIZE(kexec_arches)];
	rec->a4 = arch;
	if (RAND_BOOL())
		rec->a4 |= KEXEC_ON_CRASH;
	if (RAND_BOOL())
		rec->a4 |= KEXEC_PRESERVE_CONTEXT;
}

struct syscallentry syscall_kexec_load = {
	.name = "kexec_load",
	.num_args = 4,
	.argtype = { [3] = ARG_LIST },
	.argname = { [0] = "entry", [1] = "nr_segments", [2] = "segments", [3] = "flags" },
	.arg_params[3].list = ARGLIST(kexec_load_flags),
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_kexec_load,
};
