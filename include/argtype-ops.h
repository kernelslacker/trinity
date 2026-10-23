#pragma once

#include <stdbool.h>

#include "syscall.h"

/*
 * What the corpora do with a saved value of an argtype.  Every row of
 * argtype_table[] sets one, so a new argtype has to be classified.
 */
enum corpus_replay {
	/*
	 * Nobody classified the argtype: what a row that leaves the field
	 * out gets.  Treated as REFUSE, so an argtype is never saved and
	 * replayed raw by omission.
	 */
	CORPUS_REPLAY_UNSET = 0,

	/*
	 * Replays as saved: a length, a flag set or another plain value,
	 * or an id the kernel validates itself (key serial, timer id,
	 * SysV id, aio context), where a stale one just fails the
	 * kernel's lookup.
	 */
	CORPUS_REPLAY_KEEP,

	/*
	 * Stale in the replaying run: zeroed at save and again at load.
	 * An fd is closed or recycled by then, and a zero slot is below
	 * the stdio floor, so the mutator draws a fresh fd for it.  A
	 * pointer is an address from the saving run.  A struct buffer is
	 * a heap chunk the deferred-free queue has since released, and
	 * nested_address_scrub() accepts any in-heap address, freed
	 * chunks included.  A writable-pool slot is handed out again once
	 * the pool cursor wraps, so it holds some other call's bytes.
	 * Zero gives the kernel NULL instead.
	 */
	CORPUS_REPLAY_ZERO,

	/*
	 * Runtime-relative: a syscall with such an argument is neither
	 * saved nor replayed.  A heap pointer handed out by
	 * generic_sanitise() (iovec, pathname, sockaddr, mmap) goes stale
	 * after deferred-free eviction, and replay would feed freed
	 * memory to the kernel.  A pid valid in the saving run is
	 * meaningless in the replaying one, and dense trinity pid
	 * allocation plus kernel pid recycling means a stale pid often
	 * hits a live child or the parent: replaying kill, tkill, tgkill,
	 * pidfd_send_signal or rt_sigqueueinfo would cascade-SIGKILL the
	 * fleet.
	 */
	CORPUS_REPLAY_REFUSE,
};

/*
 * Per-argtype policy descriptor.
 *
 * Concentrates the policy that used to be spread across the giant switch
 * in generate-args.c (per-type generator body, post-call cleanup,
 * blanket address-scrub eligibility, numeric-substitute fuzzer bias,
 * fd-bias eligibility, and cross-arg length pairing) into one struct
 * per argtype.  The descriptor table is the single source of truth for
 * what each argtype is allowed to do; fill_arg, generic_free_arg and
 * blanket_address_scrub all dispatch off it, and the minicorpus and the
 * chain corpus read the replay class from it.
 */
struct argtype_ops {
	const char *name;

	/*
	 * Produce a value for an argument slot of this type.  Called from
	 * fill_arg after the metadata-driven pre-generate biases below
	 * have had a chance to fire.
	 */
	unsigned long (*generate)(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum);

	/*
	 * Post-call cleanup for resources owned by this slot's value.
	 * NULL for argtypes that own nothing freeable (the common case).
	 */
	void (*cleanup)(struct syscallrecord *rec, unsigned int argnum);

	/*
	 * Eligible for the fill_arg "re-pick a low fd that previously
	 * succeeded for this exact (syscall, argnum) slot" bias.  True
	 * for ARG_FD and every typed-fd argtype.
	 */
	bool can_use_success_fd_bias;

	/*
	 * Consults the per-slot failed_fds bitmap to bias re-rolls away
	 * from (slot, fd) pairs the kernel keeps rejecting.  True for
	 * ARG_FD and every typed-fd argtype; the typed-fd path also
	 * layers wrong-fd-type substitution on top.
	 */
	bool can_use_failed_fd_filter;

	/*
	 * Slot is eligible for the blanket post-sanitise address scrub
	 * that redirects shared_regions / libc-arena aliases to a fresh
	 * writable address before the syscall is issued.
	 */
	bool default_address_scrub;

	/*
	 * Fuzzer technique: ~1-in-8 of the time, substitute a wild
	 * numeric (rand32 / rand64) for a pool-fed identifier so the
	 * kernel's input-validation paths stay exercised.  Honoured by
	 * the per-argtype generator; the bit is metadata for table
	 * consumers / introspection.
	 */
	bool accepts_numeric_substitute;

	/*
	 * If non-ARG_UNDEFINED, this argtype expects the immediately
	 * following slot to be the named length type and will publish
	 * the chosen length there.  Replaces the hardcoded
	 * ARG_IOVEC -> ARG_IOVECLEN and ARG_SOCKADDR -> ARG_SOCKADDRLEN
	 * checks that previously lived inside the generators.
	 */
	enum argtype paired_length;

	/*
	 * What the minicorpus and the chain corpus do with a saved value
	 * of this argtype.  Every row sets it: an unset row is refused.
	 */
	enum corpus_replay replay;
};

extern const struct argtype_ops argtype_table[];
extern const unsigned int argtype_table_size;

const struct argtype_ops *argtype_get_ops(enum argtype t);
