#pragma once

#include <stdbool.h>

struct syscallrecord;

/*
 * Per-child ring of breadcrumb records for post_handler_corrupt_ptr fires.
 * The headline counter tells us a snapshot guard tripped; the breadcrumb
 * names which syscall + which arg (if known) + which scribbled value
 * triggered the rejection, so the next triage pass can attribute the
 * scribbler without a doc-archaeology hop.
 *
 * Single-writer (owning child) / single-reader (parent at periodic-dump
 * time).  Lives in childdata (alloc_shared backing), so the parent walks
 * every child's ring without IPC.  No atomics on the per-slot fields:
 * matches the corrupt_ptr_attr_record / prop_ring precedent that a torn
 * read at dump time is acceptable here -- a triage pass that sees a
 * half-written slot will skip it via the .valid gate or land on the
 * previous slot's leftover bytes, which still names a real recent fire.
 *
 * Eviction is LRU-by-position: head++ wraps around the power-of-two ring,
 * so a full ring overwrites its oldest entry rather than dropping the
 * incoming record.  64 slots per child sustains a few minutes of typical
 * fire rate before wrap, plenty of headroom between the 600 s dump
 * windows.
 */
#define CORRUPT_PTR_BREADCRUMB_SLOTS	64
#define CORRUPT_PTR_BREADCRUMB_NO_ARG	0xffu
#define CORRUPT_PTR_BREADCRUMB_SITE_LEN	16
/* Sentinel for bad_ptr when the firing callsite couldn't capture
 * the scribbled value (e.g. legacy post_handler_corrupt_ptr_bump
 * compat path).  Distinguishes "unknown" from a real 0x0 scribble
 * in dump output. */
#define CORRUPT_PTR_BREADCRUMB_BAD_UNKNOWN	((unsigned long)~0UL)

struct corrupt_ptr_breadcrumb {
	unsigned long	bad_ptr;	/* scribbled value the guard caught */
	unsigned long	iter_at_fire;	/* child->op_nr snapshot at push */
	unsigned int	syscall_nr;	/* rec->nr, or ~0u for non-syscall */
	unsigned int	arg_idx;	/* 0..MAX_ARGS-1, NO_ARG when caller
					 * cannot attribute to a specific slot */
	char		site_tag[CORRUPT_PTR_BREADCRUMB_SITE_LEN];
	bool		do32bit;
	bool		valid;
};

struct corrupt_ptr_breadcrumb_ring {
	struct corrupt_ptr_breadcrumb slots[CORRUPT_PTR_BREADCRUMB_SLOTS];
	unsigned int head;
};

/*
 * Push a breadcrumb for the current fire onto this_child()'s ring.  Safe
 * to call from any context that runs inside a child; this_child()==NULL
 * callers (parent post-mortem paths, deferred-free tick on the main
 * process) are dropped -- per-child storage has no parent fallback and
 * those callers are vanishingly rare relative to per-child fire volume.
 * site_tag may be NULL; empty string is recorded in that case.
 */
void corrupt_ptr_breadcrumb_push(const struct syscallrecord *rec,
				 unsigned int arg_idx,
				 unsigned long bad_ptr,
				 const char *site_tag);

/*
 * Walk every child's breadcrumb ring and emit up to @max_lines most-recent
 * entries via stats_log_write.  Self-rate-limited to one emission per
 * DEFENSE_DUMP_INTERVAL_SEC window so the dump cadence matches the
 * existing defense-counter rate emission and the log stays terse on
 * quiet windows.
 */
void corrupt_ptr_breadcrumb_dump(unsigned int max_lines);

/*
 * Categorise a rejected pointer value into one of four heuristic bands
 * (NULL-ish / pid-shaped / heap-shaped / kernel-VA).  Shared with the
 * shape-heuristic sample log line in utils.c so the breadcrumb dump and
 * the sample line render the same label for the same value.
 */
const char *corrupt_ptr_label(unsigned long v);
