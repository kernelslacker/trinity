#pragma once

#include <stdbool.h>
#include <stddef.h>

struct syscallrecord;

/* Writable scratch size used for every xattr name buffer.  Also the cap
 * gen_xattr_name() / gen_xattr_name_pooled() honour internally.
 */
#define XATTR_NAME_BUFSZ 256

void gen_xattr_name(char *buf, size_t len);

/*
 * Allocate a 256-byte writable buffer, fill it with a valid xattr name
 * via gen_xattr_name(), and stash the pointer in rec->aN.  argno is
 * 1-based to match the syscallrecord field naming (a1..a6).  Returns
 * false if the allocation failed or argno is out of range; callers
 * should propagate failure by leaving the slot untouched, matching the
 * pre-helper "if (!name) return;" pattern.
 */
bool sanitise_xattr_name_arg(struct syscallrecord *rec, unsigned int argno);

/* Shared flag arrays for the xattr syscall family.  Used by callers via
 * ARGLIST() in their syscallentry; non-const because struct arglist's
 * values member is unsigned long *.
 */
extern unsigned long xattr_set_flags[2];	/* XATTR_CREATE, XATTR_REPLACE */
extern unsigned long xattrat_flags[2];		/* AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH */

/*
 * On ~50% of draws, replace the (buffer, size) pair at *bufp / *sizep
 * with a curated boundary-legality bucket (NULL probe, size=0 probe,
 * 1-byte truncation, page-boundary +/- 1, huge).  The huge bucket
 * allocates a real backing buffer so the downstream allocation-cap
 * clamp does not silently shrink it.  Call BEFORE
 * avoid_shared_buffer_out().
 */
void xattr_pick_listbuf_bucket(unsigned long *bufp, unsigned long *sizep);

/*
 * Namespace-aware name generator and arg sanitiser.  Distribution:
 * ~70% curated pool, ~20% "user.<random>", ~10% fully random via
 * gen_xattr_name.  Use this in preference to sanitise_xattr_name_arg /
 * gen_xattr_name for callers that read or modify existing xattrs --
 * the unweighted prefix+suffix mix almost never lands on a name the
 * kernel can resolve, so the inode-level codepaths stay cold.
 */
void gen_xattr_name_pooled(char *buf, size_t len);
bool sanitise_xattr_name_arg_pooled(struct syscallrecord *rec, unsigned int argno);

/*
 * Same shape as xattr_pick_listbuf_bucket, but with an extra 64-byte
 * "common real xattr length" bucket -- SELinux contexts, capability
 * structs, and most user.* values fit there -- so the equality path
 * gets hit as well as the truncation/probe paths.
 */
void xattr_pick_valuebuf_bucket(unsigned long *bufp, unsigned long *sizep);

/*
 * Per-namespace value-shape generator for the setxattr family.
 * Writes a "sane enough" value (not necessarily kernel-valid in every
 * detail) into buf based on the namespace prefix of `name` and returns
 * the byte count.  user.* and trusted.* get a small random buffer.
 */
size_t xattr_fill_value(const char *name, void *buf, size_t bufsz);

/*
 * Allocate a value buffer, fill it via xattr_fill_value, and rewrite
 * (*bufp, *sizep) so the kernel sees a namespace-shaped value rather
 * than the raw random bytes from ARG_ADDRESS.  Call after the name
 * sanitiser has populated `name`.
 */
void xattr_set_value(const char *name, unsigned long *bufp, unsigned long *sizep);

/*
 * Flag-arg distribution for the setxattr family: 30% 0,
 * 30% XATTR_CREATE, 30% XATTR_REPLACE, 10% random invalid-bits.
 * Overrides the ARG_LIST draw at sanitise time so the
 * create/replace/replace-or-create decision path and the
 * flag-validation path both stay exercised.
 */
void xattr_pick_set_flags(unsigned long *flagsp);
