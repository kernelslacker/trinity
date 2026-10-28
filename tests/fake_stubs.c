/*
 * Test-binary linker glue for the PURE-module dependencies that neither the
 * fake shm nor the fake RNG covers: the allocator and output stubs
 * utils/shared_str_heap.c needs, __BUG, the struct-catalog and minicorpus
 * stubs, and mapping_sizes.  A stub for a path no test reaches aborts if
 * called, so a coverage gap fails loudly instead of misbehaving silently.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef USE_BPF
#include <linux/bpf.h>
#endif

#include "args-internal.h"
#include "debug.h"
#include "fd.h"			/* get_random_fd */
#include "maps.h"
#include "minicorpus.h"
#include "random.h"		/* rand32 */
#include "rnd.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"	/* bpf_attr_variants */
#include "utils-macros.h"	/* ARRAY_SIZE */

/*
 * mainpid, outputerr, alloc_shared: minimum needed to link
 * utils/shared_str_heap.c into the test binary.  mainpid is stamped
 * with getpid() at test start-up so shared_str_heap_init()'s parent-
 * only guard is satisfied.  alloc_shared is the fake sibling of the
 * production allocator in utils/shared_mem.c; without CONFIG_GUARD_
 * SHARED the alloc_shared_pool() macro in utils-mem.h collapses to
 * alloc_shared(), so exporting alloc_shared alone is enough to
 * satisfy the pool call sites too.  Test-binary allocs do not need
 * MAP_SHARED (single-process harness, no fork), so a plain mmap of an
 * anonymous private region is sufficient; the returned region is
 * zeroed by the kernel.
 */
pid_t mainpid;

/* Prototypes for the fakes below.  The production headers that
 * declare these (trinity.h, utils-mem.h) drag in shm/state includes
 * we intentionally don't pull into the test binary. */
void outputerr(const char *fmt, ...);
void *alloc_shared(size_t size);

void outputerr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void *alloc_shared(size_t size)
{
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (p == MAP_FAILED) {
		fprintf(stderr, "fake alloc_shared mmap %zu failed\n", size);
		abort();
	}
	return p;
}

/* The same (file, func, line, msg) payload as the production __BUG, so a
 * selftest regression prints an identifiable failure and exits non-zero
 * (ASAN folds its own report on top under -fsanitize=address). */
void __BUG(const char *bugtxt, const char *filename, const char *funcname,
	   unsigned int lineno)
{
	fprintf(stderr, "BUG: %s:%u %s: %s\n",
		filename, lineno, funcname, bugtxt);
	fflush(stderr);
	abort();
}

/*
 * The catalog the schema fill reads: args/struct_validate.c walks every row of
 * it on the first fill.  It is empty but for the bpf_attr row, which is the
 * real one, so a sanitiser that fills a bpf attr through it runs on the
 * catalog's own tables; the real struct_catalog/catalog.c would bring the
 * tables of every family into the link.
 */
const struct struct_desc struct_catalog[SC_NR_ENTRIES] = {
#include "struct_catalog/catalog-bpf.inc"
};

/*
 * Set by a test that runs a sanitiser which looks a struct up by name; the
 * lookup then finds the rows above.  Left clear, nothing is cataloged: no
 * other test lands on a live catalog lookup (the depth-cap test installs its
 * own override, and the address-walk test uses hand-built descs with no
 * FT_PTR_STRUCT descent), and NULL satisfies the linker for
 * struct_catalog/{address,variant}.c and args/struct_fill.c.
 */
bool fake_catalog_lookup;

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	if (!fake_catalog_lookup || name == NULL)
		return NULL;
	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (struct_catalog[i].name != NULL &&
		    strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}

/*
 * FOR_EACH_SYSCALL_STRUCT_ARG walks this table until it hits an entry
 * with .entries == NULL.  A single NULL-sentinel row is the empty set.
 */
const struct syscall_struct_arg_group syscall_struct_arg_groups[] = {
	{ .entries = NULL },
};

/* No-op: the attrib publishes a per-tag mutation trial into the live
 * minicorpus accounting, and a test binary has no minicorpus. */
void minicorpus_struct_field_attrib(enum field_tag tag)
{
	(void) tag;
}

/*
 * The test RNG's next draw.  The loop sanitiser linked in with
 * ioctls/loop.c takes its flags and offsets from it.
 */
unsigned int rand32(void)
{
	return rnd_u32();
}

/*
 * Minimal stubs for args/struct_fill.c symbols that are not reachable
 * via the scalar FT_FLAGS path exercised by struct_field_bounds_test.
 * They satisfy the linker; if ever called they abort so a latent
 * path-coverage gap turns into an obvious failure rather than silent
 * misbehaviour.
 *
 * get_random_fd:       only reachable via FT_FD, unless a test that runs a
 *                      sanitiser drawing from the fd pool sets
 *                      fake_random_fd_empty, when the pool hands out -1.
 * __zmalloc_tracked:  only reachable via pointer-tag passes (Pass 2/3).
 */
bool fake_random_fd_empty;

int get_random_fd(void)
{
	if (fake_random_fd_empty)
		return -1;
	fprintf(stderr, "fake get_random_fd called unexpectedly\n");
	abort();
}

/* Owned by main/params/state.c.  No -x in a test run, so the gate
 * trinity_raw_syscall() consults before it issues a syscall stays open. */
bool do_exclude_syscall;

void * __zmalloc_tracked(size_t size, const char *func)
{
	(void) func;
	void *p = calloc(1, size);

	if (!p) {
		fprintf(stderr, "fake __zmalloc_tracked: calloc(%zu) failed\n", size);
		abort();
	}
	return p;
}

/* Storage for the table get_non_null_address() indexes.  rand/random-address.c
 * is linked for the writable pool, and the real get_address() that comes with
 * it reaches the table through struct_fill.c's FT_ADDRESS fill, which no test
 * runs, so it stays zeroed. */
unsigned long mapping_sizes[NR_MAPPING_SIZES];
