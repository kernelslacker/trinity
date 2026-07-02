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
#include "struct_catalog.h"	/* struct struct_field, struct union_variant */
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
unsigned long gen_arg_struct_ptr_in(struct syscallentry *entry,
				    struct syscallrecord *rec,
				    unsigned int argnum);
unsigned long gen_arg_struct_ptr_out(struct syscallentry *entry,
				     struct syscallrecord *rec,
				     unsigned int argnum);
unsigned long gen_arg_struct_ptr_inout(struct syscallentry *entry,
				       struct syscallrecord *rec,
				       unsigned int argnum);
unsigned long gen_arg_struct_size(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum);

/*
 * Nested-address scrub entry point.  Definition lives in
 * args/scrub.c; called from blanket_address_scrub in generate-args.c
 * once the per-slot mask signals which cataloged-struct arg slots
 * carry an FT_ADDRESS field reachable through the pointer chain.
 */
void nested_address_scrub(struct syscallentry *entry,
			  struct syscallrecord *rec);

/*
 * Top-level per-slot argtype dispatch.  Definition lives in
 * args/argtype_table.c; called from generic_sanitise in
 * generate-args.c to fill each of the up-to-six syscall arg slots.
 */
unsigned long fill_arg(struct syscallentry *entry,
		       struct syscallrecord *rec,
		       unsigned int argnum);

/*
 * Struct-field fill / mutate / scrub caps shared across the args/
 * cluster.  STRUCT_FILL_MAX_FIELDS bounds the per-descriptor loop in
 * struct_fill_passes and also seeds STRUCT_MUTATE_MAX_CANDIDATES in
 * the mutator TU; PTR_ARRAY_DEFAULT_MAX caps FT_PTR_ARRAY element
 * counts in both struct_fill_passes and the scrub walker's
 * FT_PTR_ARRAY iterator.
 */
#define STRUCT_FILL_MAX_FIELDS	64U
#define PTR_ARRAY_DEFAULT_MAX	16U

/*
 * Field read/write primitives.  Definitions live in args/struct_fill.c.
 * write_field_uint plants a 1/2/4/8-byte unsigned value into a field
 * slot at its natural width (wider fields left untouched);
 * read_field_uint zero-extends the raw bytes back into a uint64_t
 * (wider fields return 0).  find_field_index_in resolves a sibling
 * FT_LEN_* / FT_PTR_* by name against the same fields[] scope the
 * fill path walks -- returns -1 on unknown name or NULL fields[].
 */
void write_field_uint(unsigned char *buf, const struct struct_field *f,
		      uint64_t val);
uint64_t read_field_uint(const unsigned char *buf,
			 const struct struct_field *f);
int find_field_index_in(const struct struct_field *fields,
			unsigned int num_fields, const char *name);

/*
 * Schema-aware struct fill helpers.  struct_fill_passes runs the
 * three-pass scalar / pointer / length fill over a fields[] array;
 * struct_variant_overlay_nested handles the depth-1 nested overlay
 * (base -> matched nested_variant) after the outer variant fill
 * lands.  Definitions live in args/struct_fill.c; consumed by
 * struct_field_fill_schema_aware in generate-args.c.
 */
void struct_fill_passes(unsigned char *buf, unsigned int size,
			const struct struct_field *fields,
			unsigned int n,
			struct syscallrecord *rec);
void struct_variant_overlay_nested(unsigned char *buf, unsigned int size,
				   const struct union_variant *variant,
				   struct syscallrecord *rec);
