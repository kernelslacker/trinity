#pragma once

/*
 * Bit-width of the writable pool buffer gen_arg_nodemask() hands out
 * for an ARG_NODEMASK slot.  1024 bits = 128 bytes = 16 unsigned longs
 * on a 64-bit build, which covers the kernel default MAX_NUMNODES so
 * the kernel's copy_from_user(ceil(maxnode/8)) stays inside the pool
 * for any caller whose advertised maxnode is capped at this value.
 *
 * Converted callers (migrate_pages, set_mempolicy, ...) MUST cap their
 * own maxnode / bit-count argument at NODEMASK_POOL_BITS so the
 * generator's buffer is large enough for the kernel's copy.  The
 * generator owns only the buffer + fill; the sibling maxnode slot is
 * a bit count (not a byte length) and stays owned by each caller's
 * .sanitise.
 */
#define NODEMASK_POOL_BITS	1024
