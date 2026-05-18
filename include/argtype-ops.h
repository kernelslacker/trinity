#pragma once

#include <stdbool.h>

#include "syscall.h"

/*
 * Per-argtype policy descriptor.
 *
 * Concentrates the policy that used to be spread across the giant switch
 * in generate-args.c (per-type generator body, post-call cleanup,
 * blanket address-scrub eligibility, numeric-substitute fuzzer bias,
 * fd-bias eligibility, and cross-arg length pairing) into one struct
 * per argtype.  The descriptor table is the single source of truth for
 * what each argtype is allowed to do; fill_arg, generic_free_arg and
 * blanket_address_scrub all dispatch off it.
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
};

extern const struct argtype_ops argtype_table[];
extern const unsigned int argtype_table_size;

const struct argtype_ops *argtype_get_ops(enum argtype t);
