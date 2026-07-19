/*
 * BPF / seccomp struct-catalog registrations.
 *
 * Covers the bpf(2) attr union, the seccomp(SECCOMP_SET_MODE_FILTER)
 * cBPF-install arm and its prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
 * legacy sibling.  setsockopt SO_ATTACH_FILTER stays bespoke because
 * that arm replaces optval wholesale before the schema-aware fill would
 * run.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <sys/prctl.h>

#include "config.h"

#include "struct_catalog.h"

#include "kernel/seccomp.h"

/*
 * seccomp(op, flags, args) op-discriminator pool.  Sibling arg a1 (op)
 * selects which struct backs the a3 pointer; the discriminator-aware
 * lookup resolves this list against rec->a1 to pick the right descriptor.
 *
 * seccomp_set_mode_filter_ops: just SECCOMP_SET_MODE_FILTER (a3 is a
 * struct sock_fprog pointer the kernel reads for cBPF install).  The
 * other three ops (SECCOMP_SET_MODE_STRICT, SECCOMP_GET_ACTION_AVAIL,
 * SECCOMP_GET_NOTIF_SIZES) point a3 at a different shape (or NULL) and
 * are not registered -- attributing CMP-learned constants against
 * sock_fprog fields on those dispatches would steer them at bytes the
 * kernel never reads as filter program.
 */
static const unsigned long seccomp_set_mode_filter_ops[] = {
	SECCOMP_SET_MODE_FILTER,
};

const struct syscall_struct_arg struct_catalog_registry_bpf[] = {
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[SC_BPF_ATTR] },
#endif
	/*
	 * seccomp a3: struct sock_fprog under SECCOMP_SET_MODE_FILTER
	 * (the cBPF install arm).  Attribution-only; bespoke
	 * sanitise_seccomp() owns the live fill via bpf_gen_seccomp().
	 * Prctl PR_SET_SECCOMP shares the shape (two-key row below);
	 * setsockopt SO_ATTACH_FILTER stays bespoke (BPF arm REPLACES
	 * optval wholesale).  See Documentation/struct_catalog.md.
	 */
	{
		"seccomp", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_values		= seccomp_set_mode_filter_ops,
		.num_discrim_values	= ARRAY_SIZE(seccomp_set_mode_filter_ops),
	},
	/*
	 * prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sock_fprog *) cBPF
	 * install arm.  Two-key row (option at a1, mode at a2).
	 * Attribution-only; bespoke sanitise_prctl() PR_SET_SECCOMP arm
	 * owns the live fill via bpf_gen_seccomp().
	 * See Documentation/struct_catalog.md.
	 */
	{
		"prctl", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_value		= PR_SET_SECCOMP,
		.discrim2_arg_idx	= 2,
		.discrim2_value		= SECCOMP_MODE_FILTER,
	},
	/* sentinel */
	{ NULL, 0, NULL },
};
