#pragma once

/*
 * Per-kind stateful name pool.
 *
 * Fresh-random name draws never reach the kernel paths where a later
 * syscall references an earlier syscall's create -- a fuzzed netdev
 * name from one call has near-zero collision odds with any name a
 * prior call planted.  The stateful arm captures recently-generated
 * names and, on a minority of draws, replays one (optionally mutated)
 * so a child's syscall stream can hit register-then-lookup,
 * create-then-delete, and similar create/reference codepaths.
 *
 * The pool is BOUNDED per kind and kind-keyed; a netdev draw never
 * returns a key-desc name and vice versa.  Storage lives in a single
 * alloc_shared_pool() region so the shared-region budget script
 * accounts for it.
 */

#include <stddef.h>

enum name_kind {
	NAME_KIND_NETDEV = 0,
	NAME_KIND_KEY_DESC,
	NAME_KIND_XATTR_NAME,
	NAME_KIND_BPF_OBJ_NAME,
	NAME_KIND_MQ_NAME,
	NAME_KIND_NETLINK_TABLE,
	NAME_KIND__MAX
};

/* Fixed small cap per kind; must be a power of two. */
#define NAME_POOL_SLOTS_PER_KIND	16
#define NAME_POOL_MAX_NAME_LEN		64

/*
 * Record a freshly-generated name into the per-kind ring.  Names
 * longer than NAME_POOL_MAX_NAME_LEN are truncated.  Caller passes
 * the byte length (NOT a NUL-terminator-inclusive length).
 */
void name_pool_record(enum name_kind kind, const char *name, size_t len);

/*
 * Try to draw a (mutated) name from the per-kind ring into @out
 * (capacity @out_cap).  Returns bytes written, or 0 if the pool for
 * @kind is empty -- caller falls back to its fresh-random generator.
 */
size_t name_pool_draw_mutated(enum name_kind kind, char *out, size_t out_cap);
