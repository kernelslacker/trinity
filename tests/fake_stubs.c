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
 *   read_field_uint,
 *   write_field_uint   -- byte-plumbing helpers cloned from
 *                         args/struct_fill.c.  Duplicated here rather
 *                         than dragging struct_fill.c (and its
 *                         zmalloc / fd / shm dep chain) into the test
 *                         link.  The two copies are semantically
 *                         identical; a future carve can hoist them
 *                         into a shared TU both binaries link.
 *
 *   struct_catalog_lookup,
 *   syscall_struct_arg_groups
 *                      -- neutral stubs: today's selftest never lands
 *                         on a live catalog lookup (the depth-cap test
 *                         installs its own lookup override, and the
 *                         address-walk test uses hand-built descs with
 *                         no FT_PTR_STRUCT descent).  The stubs
 *                         satisfy the linker for struct_catalog/
 *                         {address,variant}.c without importing the
 *                         catalog build.
 *
 *   minicorpus_struct_field_attrib
 *                      -- no-op: the attrib publishes a per-tag
 *                         mutation trial into the live minicorpus
 *                         accounting; a test binary has no minicorpus,
 *                         so drop the record on the floor.
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

void write_field_uint(unsigned char *buf, const struct struct_field *f,
		      uint64_t val)
{
	switch (f->size) {
	case 1: {
		uint8_t v = (uint8_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 2: {
		uint16_t v = (uint16_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 8: {
		uint64_t v = val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		break;
	}
}

uint64_t read_field_uint(const unsigned char *buf, const struct struct_field *f)
{
	switch (f->size) {
	case 1:
		return buf[f->offset];
	case 2: {
		uint16_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 4: {
		uint32_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 8: {
		uint64_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	default:
		return 0;
	}
}

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
