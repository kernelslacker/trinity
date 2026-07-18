/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * When KCOV CMP tracing reveals a constant that the kernel compared
 * against a struct field, we want to know which field was involved so
 * that future mutations can target that specific field.
 *
 * This module provides:
 *   - A static catalog of known struct types with field offset/size data.
 *   - A table mapping (syscall name, arg index) -> struct type.
 *   - A fast nr->desc lookup built at init time.
 *   - struct_field_for_cmp(): guess which field a CMP value belongs to.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/aio_abi.h>
#include "arch.h"		/* X86 / ARM / ... for arch-gated enum members */
#include "syscall.h"

/*
 * Semantic field-type taxonomy.
 *
 * Fields default to FT_RAW (the zero value), which preserves the
 * historical per-field random-byte fill.  Other tags carry kernel-ABI
 * vocabulary so the schema-aware fill path can produce values that
 * survive first-pass validators (size, enum bounds, flag-mask checks,
 * length-of-sibling checks, magic-version checks, fd validity).
 *
 * Implemented today: FT_RAW (fall-through), FT_FLAGS, the
 * pointer/length pair (FT_PTR_BYTES, FT_PTR_ARRAY, FT_PTR_STRUCT
 * paired with FT_LEN_BYTES / FT_LEN_COUNT).  Other tag values are
 * reserved so the catalog can be annotated incrementally; the fill
 * switch falls through to FT_RAW for tags it does not yet understand.
 */
enum field_tag {
	FT_RAW = 0,		/* current per-field random splat (default) */
	FT_ENUM,		/* pick from u.enum_.vals */
	FT_RANGE,		/* uniform [u.range.lo, u.range.hi] */
	FT_FLAGS,		/* OR a random subset of u.flags.mask bits */
	FT_PTR_BYTES,		/* pointer to byte buffer sized by sibling len field (bytes) */
	FT_PTR_ARRAY,		/* pointer to array of elements counted by sibling len field */
	FT_PTR_STRUCT,		/* pointer to one cataloged struct, length in bytes */
	FT_LEN_BYTES,		/* length-in-bytes of paired buffer field */
	FT_LEN_COUNT,		/* length-in-element-count of paired array field */
	FT_FD,			/* fd-shaped slot */
	FT_MAGIC,		/* pick from a curated constant set */
	FT_VERSION_MAGIC,	/* pick from a curated size/version set */
	FT_ADDRESS,		/* writable / scrubbable region */
	FT_TAGGED_UNION,	/* per-discriminator subset of fields */
	FT_BPF_PROGRAM,		/* eBPF insn buffer; fill delegated to net/bpf/ebpf.c generator */
	FT_VOCAB,		/* pick a NUL-padded byte string from u.vocab.vocab */
	FT_SRANGE,		/* signed uniform [u.srange.lo, u.srange.hi] */
	FT_PICKER,		/* call u.picker.pick() for the value (runtime-populated pool) */
	FT_EMBEDDED_STRUCT,	/* cataloged struct embedded in-place at the field offset (no pointer indirection) */

	/*
	 * Sentinel for per-tag-indexed counters (e.g.
	 * minicorpus_shared::mut_struct_field_trials).  Append-only: keep
	 * after the last real tag so existing tag IDs don't shift.  Any
	 * new tag is added immediately before this sentinel.
	 */
	FT_NUM_TAGS,
};

/* One field within a cataloged struct. */
struct struct_field {
	const char	*name;
	unsigned int	 offset;
	unsigned int	 size;
	enum field_tag	 tag;
	uint8_t		 mutate_weight;
	union {
		struct { const unsigned long *vals; unsigned int n; } enum_;
		struct { unsigned long lo, hi; } range;
		struct { long lo, hi; } srange;
		struct { unsigned long mask; } flags;
		/* FT_PTR_BYTES: pointer to a buffer of [1, max_bytes] bytes. */
		struct {
			const char	*len_field;
			bool		 optional;
			bool		 null_terminated;
			unsigned int	 max_bytes;
		} ptr_bytes;
		/*
		 * FT_PTR_ARRAY: pointer to [1, max_count] elements.
		 * Either elem_struct names a cataloged struct (size from
		 * its struct_size), or elem_size carries the scalar byte
		 * width directly (e.g. 8 for a u64 array).  When both are
		 * set, elem_struct wins.
		 */
		struct {
			const char	*len_field;
			const char	*elem_struct;
			unsigned int	 elem_size;
			unsigned int	 max_count;
		} ptr_array;
		/* FT_PTR_STRUCT: pointer to one cataloged struct. */
		struct {
			const char	*len_field;
			const char	*struct_name;
			bool		 optional;
		} ptr_struct;
		/*
		 * FT_LEN_BYTES / FT_LEN_COUNT: report paired buffer's
		 * chosen size.  buf_field is the single-pointer shortcut;
		 * buf_fields[] + n_buf_fields names a list of sibling
		 * pointer fields that share this LEN slot's count (e.g.
		 * kprobe_multi's cnt gates syms+addrs+cookies together).
		 * When buf_fields is set the fill pre-pins a single
		 * shared count across all listed siblings; buf_field is
		 * consulted only when buf_fields is NULL.
		 */
		struct {
			const char		*buf_field;
			const char *const	*buf_fields;
			unsigned int		 n_buf_fields;
			bool			 optional;
		} len_of;
		/*
		 * FT_VOCAB: pick one entry from a curated string pool and
		 * splat it NUL-padded across an element_stride-wide slot.
		 * element_stride matches the field width (sizeof the char
		 * array member); over-long entries are truncated with a
		 * reserved trailing NUL so the slot is always C-string safe.
		 */
		struct {
			const char *const *vocab;
			unsigned int	   vocab_len;
			unsigned int	   element_stride;
		} vocab;
		const unsigned long *vals;		/* FT_VERSION_MAGIC */
		/*
		 * FT_MAGIC: pick one fixed-size byte pattern from a curated
		 * list and splat it into the field at stride bytes.  Supports
		 * widths beyond the 1/2/4/8 scalar range -- the original
		 * motivation is struct in6_addr-shaped multicast fields where
		 * fill_field_raw() leaves a 16-byte slot at the zmalloc zero
		 * fill.  Entries may contain embedded NULs, which is why this
		 * is distinct from FT_VOCAB's strnlen / NUL-pad path.  stride
		 * must equal f->size; mismatches fall through to FT_RAW.
		 */
		struct {
			const unsigned char *const *vals;
			unsigned int		    n;
			unsigned int		    stride;
		} magic;
		/*
		 * FT_PICKER: call pick() and write the returned u64 into the
		 * field slot at the field's natural width (1/2/4/8).  The
		 * picker owns its own empty-pool fallback so the fill path
		 * never wedges: pickers fronted by a live-resource pool
		 * (tracepoint ids, fd typed-pool, etc.) must roll a random
		 * value internally when the pool is empty, so the structured
		 * fill keeps producing usable bytes on every dispatch.
		 */
		struct {
			unsigned long long (*pick)(void);
		} picker;
		/*
		 * FT_EMBEDDED_STRUCT: names a cataloged struct that lives
		 * IN-PLACE at this field's offset -- no pointer indirection,
		 * no allocation.  The fill path resolves elem_struct_name to
		 * its struct_desc and recursively schema-fills at buf +
		 * offset for the target's struct_size.  Mirrors ptr_array's
		 * elem_struct naming convention but with none of the (ptr,
		 * len) coupling that a heap-allocated array carries.
		 */
		struct {
			const char *elem_struct_name;
		} embedded_struct;
	} u;
};

/*
 * Per-discriminator-value subset of fields for a tagged-union struct.
 * When struct_desc->variants is non-NULL the schema-aware fill resolves
 * the live discriminator value (typically a syscall arg read off rec)
 * and walks the matching variant's fields[] in place of the shared
 * desc->fields[].  effective_size lets the kernel-side size byte be
 * driven by the per-variant ABI rather than sizeof(union) -- left zero
 * by variants that don't care.
 *
 * Multi-discriminator entries: when discrim_values is non-NULL the
 * resolver scans num_discrim_values entries for a match.  Lets one
 * variant claim many discriminator values without cloning the entry
 * (e.g. the cgroup link_create sub-variant matches ~20 attach types).
 * discrim_value is the single-value shortcut and is consulted only
 * when discrim_values is NULL.
 *
 * Nested tagged-union: when nested_variants is non-NULL the fill path
 * re-resolves a sub-variant against the just-filled buffer.  The
 * sub-discriminator is read from the variant's struct at byte offset
 * nested_discrim_offset (struct-relative, not buffer-relative), width
 * nested_discrim_size (1/2/4/8).  base, if set, runs once before the
 * matched sub-variant -- covers the "DEFAULT pass then specific
 * overlay" pattern used by link_create's tracing arms.  Sub-variants
 * are themselves struct union_variant, but the resolver caps recursion
 * at depth 2 -- nested-of-nested is rejected to keep the fill path
 * predictable.
 */
struct union_variant {
	unsigned long		   discrim_value;
	const unsigned long	  *discrim_values;
	unsigned int		   num_discrim_values;
	const char		  *name;
	const struct struct_field *fields;
	unsigned int		   num_fields;
	unsigned int		   effective_size;

	unsigned int		   nested_discrim_offset;
	unsigned int		   nested_discrim_size;
	const struct union_variant *base;
	const struct union_variant *nested_variants;
	unsigned int		   num_nested_variants;
};

/* A cataloged struct type with full field layout. */
struct struct_desc {
	const char		 *name;
	unsigned int		  struct_size;
	const struct struct_field *fields;
	unsigned int		  num_fields;
	/*
	 * Tagged-union plumbing.  All zero (default) means "not a tagged
	 * union" -- pre-existing structs keep their flat fields[] semantics.
	 * discrim_arg_idx is 1-based and names which syscall arg slot
	 * carries the discriminator value at fill time.
	 */
	unsigned int		   discrim_arg_idx;
	const struct union_variant *variants;
	unsigned int		   num_variants;
	/*
	 * Buffer-relative discriminator: used when the value lives at a
	 * fixed offset inside the just-filled buffer itself (e.g.
	 * sockaddr_storage's ss_family at offset 0) rather than in a
	 * syscall arg.  Consulted only when discrim_arg_idx == 0;
	 * buffer_discrim_size of 1/2/4 selects width, zero disables.
	 */
	unsigned int		   buffer_discrim_offset;
	unsigned int		   buffer_discrim_size;
};

/*
 * Static mapping of (syscall name, 1-based arg index) -> struct type.
 * Terminated by .syscall_name == NULL.
 *
 * Optional sibling-arg discriminator: when discrim_arg_idx != 0 the
 * entry only applies if rec->a<discrim_arg_idx> matches discrim_value
 * (or any value in discrim_values[0..num_discrim_values)).  Entries
 * with discrim_arg_idx == 0 are the slot's "default" and are consulted
 * only if no discriminated entry matched -- so existing non-
 * discriminated registrations stay byte-identical and resolve exactly
 * as before.  At most one default per (name, arg_idx); discriminated
 * variants are walked in registration order, first match wins.
 *
 * Packed discriminators: some syscalls pack the discriminator into a
 * single arg alongside an unrelated subfield (e.g. quotactl's a1 is
 * QCMD(subcmd, type) == (subcmd << 8) | (type & 0xff), so the cmd
 * subfield -- the one that actually selects which struct the kernel
 * reads at a4 -- lives in the high bits).  Optional discrim_shift /
 * discrim_mask extract the meaningful subfield before the match:
 * the lookup tests
 *   ((rec->a<discrim_arg_idx> >> discrim_shift) & effective_mask)
 *      == discrim_value (or any discrim_values[] entry)
 * where effective_mask is discrim_mask when set and ~0UL otherwise.
 * Both fields default to zero, which gives the historical exact-match
 * semantics -- all existing registrations stay byte-identical.
 *
 * This is a DIFFERENT axis from the in-buffer struct_desc->variants
 * resolved by struct_desc_resolve_variant(): variants pick a field
 * subset INSIDE an already-chosen descriptor based on a value WITHIN
 * the just-filled buffer (or a syscall arg); the discriminator below
 * picks which descriptor a slot resolves to in the first place, based
 * on a sibling syscall arg.  A slot can use both: the discriminator
 * picks the descriptor, and the descriptor's variants pick the field
 * subset within it.
 */
struct syscall_struct_arg {
	const char		 *syscall_name;
	unsigned int		  arg_idx;	/* 1-based */
	const struct struct_desc *desc;
	unsigned int		  discrim_arg_idx;	/* 1-based; 0 = default */
	unsigned long		  discrim_value;	/* single-value shortcut */
	const unsigned long	 *discrim_values;	/* multi-value match-list */
	unsigned int		  num_discrim_values;
	unsigned int		  discrim_shift;	/* right-shift applied to the raw arg before match (0 = none) */
	unsigned long		  discrim_mask;		/* AND-mask applied after the shift (0 = no mask, i.e. all bits) */
	/*
	 * Optional second discriminator key (symmetric to the first).
	 * When discrim2_arg_idx != 0 the entry matches iff BOTH key1 and
	 * key2 match.  Zero-default keeps every pre-extension registration
	 * byte-identical: a single-key entry leaves all discrim2_* at 0
	 * and the lookup skips the second extract+compare entirely.
	 *
	 * Designed for the setsockopt (level, optname) shape -- one sibling
	 * arg picks a level, a second picks an optname inside that level,
	 * and optname numbers are scoped to level rather than globally
	 * unique, so a single-key discriminator on optname alone would
	 * catastrophically misattribute (IPV6_TCLASS == IP_TOS == 1 etc.).
	 * shift/mask are kept symmetric so a future packed two-key consumer
	 * (some ioctl families) does not need a third extension.
	 */
	unsigned int		  discrim2_arg_idx;	/* 1-based; 0 = single-key */
	unsigned long		  discrim2_value;
	const unsigned long	 *discrim2_values;
	unsigned int		  num_discrim2_values;
	unsigned int		  discrim2_shift;
	unsigned long		  discrim2_mask;
};

/*
 * Stable indices into struct_catalog[].  Each entry uses C99 designated
 * initialisers ([SC_FOO] = {...}) so adding / removing slots -- including
 * #ifdef-gated ones -- doesn't shift the index of any other entry.
 * syscall_struct_args[] addresses entries by SC_X rather than by raw
 * integer, so #ifdef-gated catalog entries no longer force the syscall
 * map to fork into per-configure branches.
 *
 * Each SC_X enum constant is gated by the same #ifdef as its catalog
 * slot, so a referenced-but-disabled entry is a compile error.
 */
enum struct_catalog_idx {
	SC_TIMEX,
	SC_SCHED_ATTR,
	SC_CLONE_ARGS,
	SC_IO_URING_PARAMS,
	SC_RLIMIT,
	SC_ITIMERSPEC,
	SC_EPOLL_EVENT,
	SC_PERF_EVENT_ATTR,
	SC_SIGACTION,
	SC_MSGHDR,
	SC_SOCKADDR_STORAGE,
	SC_LANDLOCK_RULESET_ATTR,
	SC_MNT_ID_REQ,
	SC_USER_CAP_HEADER,
	SC_USER_CAP_DATA,
	SC_FUTEX_WAITV,
	SC_STACK_T,
	SC_SIGINFO_T,
	SC_MQ_ATTR,
	SC_MSQID_DS,
	SC_SCHED_PARAM,
	SC_IO_URING_REGISTER_ARGS,
#ifdef USE_BPF
	SC_BPF_ATTR,
	SC_BPF_INSN,
#endif
	SC_IOVEC,
	SC_TIMESPEC,
	SC_CACHESTAT_RANGE,
	SC_MOUNT_ATTR,
	SC_SEMBUF,
	SC_POLLFD,
	SC_OPEN_HOW,
	SC_SIGEVENT,
	SC_ROBUST_LIST_HEAD,
	SC_RSEQ,
	SC_ITIMERVAL,
	SC_UTIMBUF,
	SC_FLOCK,
	SC_TIMEVAL,
	SC_TIMEZONE,
	SC_NS_ID_REQ,
#ifdef USE_XATTR_ARGS
	SC_XATTR_ARGS,
#endif
	SC_FILE_ATTR,
	SC_LANDLOCK_PATH_BENEATH_ATTR,
	SC_F_OWNER_EX,
	SC_LANDLOCK_NET_PORT_ATTR,
	SC_IF_DQBLK,
	SC_IF_DQINFO,
#ifdef X86
	SC_USER_DESC,
#endif
#if defined(__x86_64__) || defined(__aarch64__)
	SC_PT_REGS,
	SC_USER_REGS_STRUCT,
#endif
	SC_SOCK_FILTER,
	SC_SOCK_FPROG,
	SC_SHMID_DS,
	SC_IOCB,
	/*
	 * setsockopt optval struct shapes -- first batch (the proof) for
	 * the two-key (level, optname) discriminator.  Registered against
	 * ("setsockopt", arg 4) with discrim_arg_idx=2 (level) and
	 * discrim2_arg_idx=3 (optname); resolution goes through
	 * struct_arg_lookup_two_key() from apply_sockopt_entry(), not the
	 * rec-based path.
	 */
	SC_LINGER,
	SC_IP_MREQN,
	SC_IPV6_MREQ,
	SC_PACKET_MREQ,
	SC_GROUP_REQ,
#ifdef USE_TCP_REPAIR_OPT
	SC_TCP_REPAIR_OPT,
#endif
#ifdef USE_SCTP
	SC_SCTP_INITMSG,
	SC_SCTP_RTOINFO,
	SC_SCTP_ASSOCPARAMS,
	SC_SCTP_SETADAPTATION,
	SC_SCTP_ASSOC_VALUE,
	SC_SCTP_SNDINFO,
	SC_SCTP_SNDRCVINFO,
	SC_SCTP_EVENT_SUBSCRIBE,
	SC_SCTP_AUTHCHUNK,
	SC_SCTP_SACK_INFO,
	SC_SCTP_AUTHKEYID,
	SC_SCTP_DEFAULT_PRINFO,
	SC_SCTP_ADD_STREAMS,
	SC_SCTP_STREAM_VALUE,
	SC_SCTP_EVENT,
	SC_SCTP_PADDRTHLDS,
	SC_SCTP_PADDRTHLDS_V2,
	SC_SCTP_UDPENCAPS,
	SC_SCTP_PADDRPARAMS,
	SC_SCTP_PROBEINTERVAL,
	SC_SCTP_PRIM,
#endif
	SC_FILE_HANDLE,
	SC_FS_DISK_QUOTA,
	SC_MMSGHDR,
	SC_GROUP_SOURCE_REQ,
	SC_IP_MREQ_SOURCE,
	SC_MSGBUF,
	SC_SIGSET_T,
	SC_LSM_CTX,
	SC_KEXEC_SEGMENT,
	SC_KEYCTL_PAYLOAD,
	SC_UFFDIO_RANGE,
	SC_UFFDIO_API,
	SC_UFFDIO_REGISTER,
	SC_UFFDIO_COPY,
	SC_UFFDIO_ZEROPAGE,
#ifdef USE_IF_ALG
	SC_AF_ALG_IV,
#endif

	SC_NR_ENTRIES,		/* sentinel; equals ARRAY_SIZE(struct_catalog) once both stay in lockstep */
};

_Static_assert(SC_NR_ENTRIES <= 256,
	       "struct_catalog sanity ceiling");

/* All cataloged struct types. */
extern const struct struct_desc struct_catalog[];

/*
 * Syscall -> struct arg mapping table, split by domain.
 *
 * Registration entries live in the per-domain arrays under
 * struct_catalog/registry/; struct_catalog/registry.c composes them
 * into syscall_struct_arg_groups[], a NULL-terminated table of
 * per-domain arrays.  Each per-domain array is itself NULL-terminated
 * on syscall_name, so the two-level walk is:
 *
 *   FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) { ... use sa ... }
 *
 * or the equivalent explicit form used by legacy call sites.
 */
struct syscall_struct_arg_group {
	const struct syscall_struct_arg *entries;
};

extern const struct syscall_struct_arg_group syscall_struct_arg_groups[];

#define FOR_EACH_SYSCALL_STRUCT_ARG(_g, _sa)					\
	for ((_g) = syscall_struct_arg_groups; (_g)->entries != NULL; (_g)++)	\
		for ((_sa) = (_g)->entries; (_sa)->syscall_name != NULL; (_sa)++)

/*
 * Find the struct_desc for a given struct name.
 * Returns NULL if not in the catalog.
 */
const struct struct_desc *struct_catalog_lookup(const char *name);

/*
 * Find which struct (if any) syscall nr uses at arg_idx (1-based).
 * do32bit selects the 32-bit or 64-bit table on biarch builds.
 * Returns NULL if not cataloged.
 * Must be called after struct_catalog_init().
 *
 * rec drives the cmd-style discriminator: when one or more
 * syscall_struct_args[] entries for this (nr, arg_idx) carry a
 * non-zero discrim_arg_idx, the lookup reads rec->a<discrim_arg_idx>
 * and returns the first entry whose discrim_value (or discrim_values[])
 * matches.  No-match falls through to the slot's default entry (or
 * NULL when none registered).  Pass rec == NULL to skip the
 * discriminator walk and always return the default desc -- the right
 * choice for callers that have no live syscall args (e.g. table-init
 * paths).  Slots with no discriminated entries are unaffected by rec.
 */
const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec);

/*
 * Explicit-key two-key lookup for callers that already hold the live
 * discriminator values and have NOT yet committed them to rec->aN.
 * setsockopt is the canonical consumer: do_setsockopt() picks
 * (so->level, so->optname) into a local sockopt struct before any
 * optname mangling and before publishing the values to rec->a2/a3, so
 * reading rec at fill time would either miss the live keys or capture
 * the mangled (post-rand-OR) optname.
 *
 * Walks syscall_struct_args[] for entries matching (name, arg_idx) and
 * returns the first whose (k1, k2) match the entry's
 * (discrim_value/values, discrim2_value/values) under the same
 * shift/mask logic as struct_arg_lookup().  Entries that carry no
 * second key (discrim2_arg_idx == 0) are skipped here -- this entry
 * point only resolves genuine two-key rows.  Returns NULL on no match.
 */
const struct struct_desc *struct_arg_lookup_two_key(const char *name,
						    unsigned int arg_idx,
						    unsigned long k1,
						    unsigned long k2);

/*
 * Given a CMP hint value and a struct descriptor, return the index of
 * a field whose size can naturally contain the value, or -1 if no
 * field matches.  Used to associate a kernel CMP constant with the
 * struct field most likely being compared.  When desc carries a
 * tagged-union variant set and rec is non-NULL, the candidate pool is
 * scoped to the live variant resolved from rec; otherwise the full
 * desc->fields[] is sampled.  Passing rec == NULL preserves the
 * pre-variant behaviour for non-union structs.
 *
 * Field reference: the returned index addresses either the resolved
 * variant's fields[] (when scoped) or desc->fields[] (when not).
 * Callers that want to read the field directly must mirror the same
 * lookup; an opaque-index API would force the same walk on the read
 * side without any reuse benefit.
 */
struct syscallrecord;
int struct_field_for_cmp(const struct struct_desc *desc,
			 struct syscallrecord *rec, unsigned long val);

/*
 * Resolve which union_variant applies to a given (desc, rec, buf) tuple.
 * Two discriminator sources are supported, in priority order:
 *
 *   - desc->discrim_arg_idx > 0: read a syscall arg off rec.  buf is
 *     unused on this path.  rec must be non-NULL.
 *   - desc->buffer_discrim_size > 0: read the discriminator from
 *     buf + desc->buffer_discrim_offset at the indicated width.  Used
 *     when the live discriminator was just written into the buffer by
 *     the scalar pass (e.g. sockaddr_storage's ss_family).  buf must
 *     be non-NULL on this path; pass NULL to opt out (e.g. from CMP
 *     paths that run before the next fill).
 *
 * Returns NULL when desc carries no variants, when the active
 * discriminator source is unreadable, or when the discriminator value
 * matches no variant.
 */
const struct union_variant *
struct_desc_resolve_variant(const struct struct_desc *desc,
			    struct syscallrecord *rec,
			    const unsigned char *buf);

/*
 * Re-resolve the nested sub-variant for an outer variant whose buffer
 * has already been filled.  The sub-discriminator is read from buf at
 * outer->nested_discrim_offset using outer->nested_discrim_size bytes,
 * then linear-scanned against outer->nested_variants[].  Returns NULL
 * when outer has no nested table, when buf is too small for the
 * discriminator field, or when no nested entry matches.  Callers that
 * need the more specific effective_size (e.g. sanitise_bpf default
 * arm) prefer the nested return when non-NULL.
 */
const struct union_variant *
struct_desc_resolve_nested_variant(const struct union_variant *outer,
				   const unsigned char *buf,
				   unsigned int size);

/*
 * Schema-aware per-field fill for a cataloged struct.  Three passes
 * (scalar / pointer / length) resolve tag-driven coupling without an
 * init-time topological sort; FT_RAW fields keep the historical
 * per-field random splat byte-for-byte.  When desc carries variants,
 * the live discriminator on rec selects which variant's fields[] is
 * walked; the parent rec is also threaded into nested FT_PTR_STRUCT
 * fills so a child struct reads the same syscall args.
 *
 * Public so per-syscall sanitisers (e.g. sanitise_bpf's default arm)
 * can lean on schema fill for cmds they don't customise; arg-gen
 * callers in generate-args.c continue to use this directly.
 */
void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec);

/*
 * Post-fill structure-aware mutator.  Runs immediately after
 * struct_field_fill_schema_aware() at the top-level ARG_STRUCT_PTR_IN /
 * ARG_STRUCT_PTR_INOUT call sites; with bounded probability picks one
 * mutable-tagged field and applies a tag-respecting neighbour mutation
 * in place.  Skip-list (FT_PTR_*, FT_LEN_*, FT_ADDRESS, FT_FD,
 * FT_BPF_PROGRAM, FT_TAGGED_UNION) fields are never candidates so the
 * (ptr, len) coupling and address / fd validity invariants the fill
 * resolves stay intact.  Variant resolution receives the live post-fill
 * buf so buffer-derived discriminators (e.g. sockaddr_storage's
 * ss_family) scope correctly.
 */
void struct_field_mutate_one(unsigned char *buf, unsigned int size,
			     const struct struct_desc *desc,
			     struct syscallrecord *rec);

/*
 * Behavioural self-test for the per-tag post-fill mutator primitives
 * and the skip-list discipline.  One-shot, called from the parent in
 * init_shm_publish_and_subsystems() before any child forks.  BUG()s on
 * failure -- trinity has no separate unit-test binary, so a regression
 * in the in-buffer mutator (wrong-mask flag bit, out-of-vocab enum,
 * skip-listed field touched) must fail the run loudly here rather than
 * propagate silently into fuzz output.
 */
void struct_field_mutate_self_check(void);

/*
 * Build the fast nr->desc lookup table by resolving syscall names in
 * syscall_struct_args[] against the active syscall table.
 * Must be called after select_syscall_tables().
 */
void struct_catalog_init(void);

/*
 * Linear search through syscall_struct_args[] for an entry matching
 * (name, arg_idx) and return its struct_desc.  Returns NULL if no
 * mapping exists.  Suitable for table-init paths that run before
 * struct_catalog_init() has populated the nr-indexed table; per-
 * dispatch consumers should use struct_arg_lookup() instead.
 */
const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx);

/*
 * True if desc (or any cataloged struct reachable from desc via
 * FT_PTR_STRUCT / FT_PTR_ARRAY) carries an FT_ADDRESS field.  Used at
 * table-init time to decide whether nested address-scrub needs to walk
 * the struct on every dispatch.  Bounded recursion guards against
 * future catalog entries with cyclic references.
 */
bool struct_desc_has_address_field(const struct struct_desc *desc);

/*
 * True if ANY syscall_struct_args[] entry for (name, arg_idx) -- the
 * default entry and every discriminator variant -- reaches an
 * FT_ADDRESS field.  The nested-address-scrub mask is a conservative
 * include: if any variant the slot could resolve to carries an address
 * field, the slot must be walked every dispatch.  Suitable for table-
 * init paths that run before struct_catalog_init() has populated the
 * nr-indexed table.
 */
bool struct_arg_any_has_address_field(const char *name, unsigned int arg_idx);
