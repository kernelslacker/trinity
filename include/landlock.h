#pragma once

#include <stdbool.h>
#include <linux/types.h>

/*
 * Make a ruleset that handles the LANDLOCK_PERMISSION_* bits in @handled allow
 * every member of them, as fds/landlock.c explains.  Called on a ruleset before
 * anything can restrict itself with it.  False means a rule was refused: the
 * ruleset still denies what it handles, and the caller closes it.
 */
bool landlock_allow_permissions(int ruleset_fd, __u64 handled);

/*
 * Make a ruleset that handles the filesystem rights in @handled_fs allow every
 * one of them beneath the tmp dir, where a child that restricts itself with it
 * makes its bug log.  False means the rule was refused, and the caller closes
 * the ruleset.
 */
bool landlock_allow_tmpdir(int ruleset_fd, __u64 handled_fs);
