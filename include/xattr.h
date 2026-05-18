#pragma once

#include <stdbool.h>
#include <stddef.h>

struct syscallrecord;

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
