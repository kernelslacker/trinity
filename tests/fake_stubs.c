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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"
#include "minicorpus.h"
#include "struct_catalog.h"

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
