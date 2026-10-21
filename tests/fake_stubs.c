/*
 * Test-binary linker glue for the remaining PURE-module dependencies
 * that neither the fake shm nor the fake RNG covers.
 *
 * Contents:
 *
 *   __BUG              -- abort with the same (file, func, line, msg)
 *                         payload the production __BUG surfaces, so a
 *                         selftest regression prints an identifiable
 *                         failure and exits non-zero (ASAN then folds
 *                         its own report on top when running under
 *                         -fsanitize=address).
 *
 *   struct_catalog_lookup,
 *   syscall_struct_arg_groups
 *                      -- neutral stubs: today's selftest never lands
 *                         on a live catalog lookup (the depth-cap test
 *                         installs its own lookup override, and the
 *                         address-walk test uses hand-built descs with
 *                         no FT_PTR_STRUCT descent).  The stubs
 *                         satisfy the linker for struct_catalog/
 *                         {address,variant}.c and args/struct_fill.c
 *                         without importing the catalog build.
 *
 *   minicorpus_struct_field_attrib
 *                      -- no-op: the attrib publishes a per-tag
 *                         mutation trial into the live minicorpus
 *                         accounting; a test binary has no minicorpus,
 *                         so drop the record on the floor.
 *
 *   get_random_fd,
 *   ebpf_gen_program_into,
 *   struct_field_fill_schema_aware,
 *   __zmalloc_tracked  -- minimal stubs to satisfy args/struct_fill.c's
 *                         pointer-tag / BPF / schema-fill / alloc paths.
 *                         The struct_field_bounds_test only exercises the
 *                         scalar FT_FLAGS path in Pass 1; none of these
 *                         are reachable when the bounds guard fires first
 *                         (after the fix) or when the process crashes
 *                         before reaching them (before the fix).
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "args-internal.h"
#include "debug.h"
#include "minicorpus.h"
#include "struct_catalog.h"

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

void __BUG(const char *bugtxt, const char *filename, const char *funcname,
	   unsigned int lineno)
{
	fprintf(stderr, "BUG: %s:%u %s: %s\n",
		filename, lineno, funcname, bugtxt);
	fflush(stderr);
	abort();
}

/*
 * args/struct_fill.c is now in REAL_SRCS; it provides the canonical
 * write_field_uint / read_field_uint implementations.  The stubs that
 * used to live here have been removed to avoid duplicate-symbol link
 * errors.  The behaviour is identical -- the old comment described them
 * as "semantically identical" copies.
 */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	(void) name;
	return NULL;
}

/*
 * FOR_EACH_SYSCALL_STRUCT_ARG walks this table until it hits an entry
 * with .entries == NULL.  A single NULL-sentinel row is the empty set.
 */
const struct syscall_struct_arg_group syscall_struct_arg_groups[] = {
	{ .entries = NULL },
};

void minicorpus_struct_field_attrib(enum field_tag tag)
{
	(void) tag;
}

/*
 * Minimal stubs for args/struct_fill.c symbols that are not reachable
 * via the scalar FT_FLAGS path exercised by struct_field_bounds_test.
 * They satisfy the linker; if ever called they abort so a latent
 * path-coverage gap turns into an obvious failure rather than silent
 * misbehaviour.
 *
 * rand32, get_address: only reachable via fill_field_raw / FT_ADDRESS;
 *   neither tag is used in the bounds test.
 * get_random_fd:       only reachable via FT_FD.
 * ebpf_gen_program_into: only reachable via FT_BPF_PROGRAM (USE_BPF).
 * struct_field_fill_schema_aware: only reachable via FT_EMBEDDED_STRUCT.
 * __zmalloc_tracked:  only reachable via pointer-tag passes (Pass 2/3).
 */
unsigned int rand32(void)
{
	fprintf(stderr, "fake rand32 called unexpectedly\n");
	abort();
}

void *get_address(void)
{
	fprintf(stderr, "fake get_address called unexpectedly\n");
	abort();
}

int get_random_fd(void)
{
	fprintf(stderr, "fake get_random_fd called unexpectedly\n");
	abort();
}

/* ebpf_gen_program_into signature uses struct bpf_insn * but we avoid
 * pulling in bpf.h here; void * is ABI-equivalent on all supported arches. */
void ebpf_gen_program_into(void *insns, int max_insns,
			   int *insn_count, unsigned int prog_type)
{
	(void) insns; (void) max_insns; (void) insn_count; (void) prog_type;
	fprintf(stderr, "fake ebpf_gen_program_into called unexpectedly\n");
	abort();
}

void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec)
{
	(void) buf; (void) size; (void) desc; (void) rec;
	fprintf(stderr, "fake struct_field_fill_schema_aware called unexpectedly\n");
	abort();
}

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
