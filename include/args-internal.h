#pragma once

/*
 * Internal header for the args/ cluster.  Holds prototypes and shared
 * constants for helpers that cross cluster boundaries within the
 * generate-args carve but are not part of the public argtype-ops /
 * sanitise API.
 *
 * The public API lives in include/argtype-ops.h, include/sanitise.h,
 * and include/arg-len-semantics.h; anything callers outside args/
 * need continues to be declared there.  This header is private to the
 * args/ subdirectory and the generate-args driver.
 */

#include <stdbool.h>
#include <stdint.h>

#include "kcov.h"		/* enum cmp_hint_callsite */
#include "syscall.h"		/* struct syscallentry, struct syscallrecord, enum argtype */

/*
 * cmp-hint injection rate + credit-stamp helpers.  Definitions live in
 * args/cmp_hint_inject.c.
 *
 * cmp_hint_inject_denom() resolves the ONE_IN denom for a callsite's
 * baseline (16 for the ARG_RANGE/OP/LIST callsites, 9 for the
 * gen_undefined_arg case-0 shortcut, 10 for the ARG_STRUCT_SIZE
 * fallback), amplifying to 4 during a plateau-driven rescue.
 *
 * cmp_hint_baseline_should_inject() folds the per-child A/B baseline
 * gate around cmp_hint_inject_denom().  Used only at the three
 * BASELINE callsites; the AMPLIFIED callsites keep calling
 * cmp_hint_inject_denom() directly.
 *
 * credit_cmp_hint_injection() runs at every callsite that commits an
 * injected hint, keeping the observability counters and the per-call
 * latch in lock-step.
 */
unsigned int cmp_hint_inject_denom(unsigned int baseline);
bool cmp_hint_baseline_should_inject(void);
void credit_cmp_hint_injection(struct syscallrecord *rec,
			       enum cmp_hint_callsite callsite);

/*
 * Classic argtype handlers.  Definitions live in args/handle_arg.c;
 * their addresses are taken by the argtype_table[] dispatch descriptor
 * in generate-args.c and by nothing else outside args/.
 */
unsigned long handle_arg_address(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum);
unsigned long handle_arg_range(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long handle_arg_op(struct syscallentry *entry,
			    struct syscallrecord *rec,
			    unsigned int argnum);
unsigned long handle_arg_list(struct syscallentry *entry,
			      struct syscallrecord *rec,
			      unsigned int argnum);
unsigned long handle_arg_iovec(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long handle_arg_iovec_in(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum);
unsigned long handle_arg_sockaddr(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum);
unsigned long handle_arg_mode_t(struct syscallentry *entry,
				struct syscallrecord *rec,
				unsigned int argnum);

/*
 * Publish a paired-length value into the slot after argnum if the
 * argtype at argnum declares a paired_length in the descriptor table
 * and the next slot is of that paired type.  Definition lives in
 * args/handle_arg.c; consumed by handle_arg_iovec_dir /
 * handle_arg_sockaddr in that TU and by gen_arg_buf_sized in
 * generate-args.c.
 */
void publish_paired_length(struct syscallentry *entry,
			   struct syscallrecord *rec,
			   unsigned int argnum,
			   unsigned long len);

/*
 * Per-argtype thin generators used by argtype_table[].  Each function
 * lives in its owning cluster TU inside args/ and is referenced only
 * by name from the argtype_table[] entries in generate-args.c.
 */
unsigned long gen_undefined_arg(struct syscallentry *entry,
				struct syscallrecord *rec,
				unsigned int argnum);
unsigned long gen_arg_fd(struct syscallentry *entry,
			 struct syscallrecord *rec,
			 unsigned int argnum);
unsigned long gen_arg_typed_fd(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long gen_arg_len(struct syscallentry *entry,
			  struct syscallrecord *rec,
			  unsigned int argnum);
unsigned long gen_arg_non_null_address(struct syscallentry *entry,
				       struct syscallrecord *rec,
				       unsigned int argnum);
unsigned long gen_arg_mmap(struct syscallentry *entry,
			   struct syscallrecord *rec,
			   unsigned int argnum);
unsigned long gen_arg_pid(struct syscallentry *entry,
			  struct syscallrecord *rec,
			  unsigned int argnum);
unsigned long gen_arg_key_serial(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum);
unsigned long gen_arg_timerid(struct syscallentry *entry,
			      struct syscallrecord *rec,
			      unsigned int argnum);
unsigned long gen_arg_aio_ctx(struct syscallentry *entry,
			      struct syscallrecord *rec,
			      unsigned int argnum);
unsigned long gen_arg_sem_id(struct syscallentry *entry,
			     struct syscallrecord *rec,
			     unsigned int argnum);
unsigned long gen_arg_msg_id(struct syscallentry *entry,
			     struct syscallrecord *rec,
			     unsigned int argnum);
unsigned long gen_arg_sysv_shm(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long gen_arg_cpu(struct syscallentry *entry,
			  struct syscallrecord *rec,
			  unsigned int argnum);
unsigned long gen_arg_numa_node(struct syscallentry *entry,
				struct syscallrecord *rec,
				unsigned int argnum);
unsigned long gen_arg_pathname(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long gen_arg_xattr_name(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum);
unsigned long gen_arg_fstype_name(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum);
unsigned long gen_arg_timespec(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long gen_arg_buf_sized(struct syscallentry *entry,
				struct syscallrecord *rec,
				unsigned int argnum);
unsigned long gen_arg_itimerval(struct syscallentry *entry,
				struct syscallrecord *rec,
				unsigned int argnum);
unsigned long gen_arg_itimerspec(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum);
unsigned long gen_arg_timeval(struct syscallentry *entry,
			      struct syscallrecord *rec,
			      unsigned int argnum);
unsigned long gen_arg_nodemask(struct syscallentry *entry,
			       struct syscallrecord *rec,
			       unsigned int argnum);
unsigned long gen_arg_cpumask(struct syscallentry *entry,
			      struct syscallrecord *rec,
			      unsigned int argnum);
unsigned long gen_arg_paired_length(struct syscallentry *entry,
				    struct syscallrecord *rec,
				    unsigned int argnum);
unsigned long gen_arg_socketinfo(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum);
