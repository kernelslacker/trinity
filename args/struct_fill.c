#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#ifdef USE_BPF
#include "bpf.h"
#endif
#include "deferred-free.h"		// zmalloc_tracked
#include "fd.h"				// get_random_fd
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "utils.h"

/*
 * Per-field FT_RAW splat: the historical strategy.  Splats a fresh
 * random value into every addressable field of natural width <= 4
 * bytes.  Wider fields (typically pointers and u64 flags) are left at
 * the buffer's initial fill -- a random 8-byte value in a pointer
 * slot just bounces at copy_from_user with -EFAULT and would starve
 * every other field of fuzz coverage.
 */
static void fill_field_raw(unsigned char *buf, const struct struct_field *f)
{
	switch (f->size) {
	case 1:
		buf[f->offset] = (unsigned char) rand32();
		break;
	case 2: {
		uint16_t v = (uint16_t) rand32();
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = rand32();
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		/* leave wider fields at the buffer's initial fill */
		break;
	}
}

/*
 * FT_FLAGS: OR a random subset of the valid-bit mask into the field
 * slot.  Each bit in u.flags.mask is independently included with 50%
 * probability via a single rnd_u64() draw, so the kernel sees a
 * mask-valid value rather than the splat's random byte pattern.  Bits
 * outside the mask are never set, which keeps the call past the
 * kernel's "unknown flags" rejection on the first iteration.
 */
static void fill_field_flags(unsigned char *buf, const struct struct_field *f)
{
	uint64_t val = f->u.flags.mask & rnd_u64();

	switch (f->size) {
	case 1: {
		uint8_t v = (uint8_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 2: {
		uint16_t v = (uint16_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 8: {
		uint64_t v = val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		break;
	}
}

/*
 * Write a 1/2/4/8-byte unsigned value into the field slot.  Wider
 * fields are left untouched -- the same conservative shape as
 * fill_field_flags.  Used by the FT_LEN_* and FT_PTR_* implementations
 * to plant length values and pointer values at the right width
 * without per-call-site size dispatch.
 */
void write_field_uint(unsigned char *buf, const struct struct_field *f,
			     uint64_t val)
{
	switch (f->size) {
	case 1: {
		uint8_t v = (uint8_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 2: {
		uint16_t v = (uint16_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 8: {
		uint64_t v = val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		break;
	}
}

/*
 * Read a 1/2/4/8-byte unsigned field as a uint64_t.  Wider fields
 * return 0 -- the only callers (the FT_ADDRESS scrub recursion and the
 * FT_PTR_ARRAY count read) only care about pointer- and length-sized
 * slots, which are at most 8 bytes wide.
 */
uint64_t read_field_uint(const unsigned char *buf,
				const struct struct_field *f)
{
	switch (f->size) {
	case 1:
		return buf[f->offset];
	case 2: {
		uint16_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 4: {
		uint32_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 8: {
		uint64_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	default:
		return 0;
	}
}

/* Linear name lookup over a struct's field array. */
int find_field_index_in(const struct struct_field *fields,
			       unsigned int num_fields, const char *name)
{
	unsigned int i;

	if (name == NULL)
		return -1;
	for (i = 0; i < num_fields; i++) {
		if (strcmp(fields[i].name, name) == 0)
			return (int) i;
	}
	return -1;
}

/*
 * Caps and per-iteration bias for the FT_PTR_* family.  Defaults apply
 * when the field's annotation leaves max_bytes / max_count at zero.
 * OPTIONAL_PRESENT_PCT is the bias toward "buffer present" for fields
 * marked .optional = true; the remainder rolls NULL pointer + 0 length
 * so the NULL-args kernel path also gets exercised.
 */
#define PTR_BYTES_DEFAULT_MAX	4096U
#define OPTIONAL_PRESENT_PCT	80U

/* True ~OPTIONAL_PRESENT_PCT% of the time. */
static bool optional_present(void)
{
	return rnd_modulo_u32(100) < OPTIONAL_PRESENT_PCT;
}

/*
 * Random-byte fill into a freshly-allocated sub-buffer.  Used by
 * FT_PTR_BYTES so cmsg-style parsers see varied bytes rather than the
 * zero fill zmalloc hands back.  When null_terminate is set, the last
 * byte is forced to NUL so the kernel's cstring path (strnlen_user,
 * etc.) sees a terminated buffer rather than walking off the end.
 */
static void random_byte_fill(unsigned char *p, unsigned long nbytes,
			     bool null_terminate)
{
	unsigned long j;

	for (j = 0; j < nbytes; j++)
		p[j] = (unsigned char) rnd_u32();
	if (null_terminate && nbytes > 0)
		p[nbytes - 1] = 0;
}

/*
 * Schema-aware field fill: dispatch on f->tag and produce a
 * tag-respecting value, falling back to the FT_RAW per-field random
 * splat for tags this build does not yet specialise.
 *
 * All catalog entries default to FT_RAW; an unannotated struct
 * therefore produces byte-identical output to the pre-schema
 * struct_field_fill -- the rand32() call sequence is preserved
 * field-for-field, width-for-width.  As individual structs migrate
 * to FIELDX() annotations, their fields begin consuming the per-tag
 * mutators below.
 *
 * Three passes resolve the cross-field coupling between PTR and LEN
 * tags without an init-time topological sort:
 *
 *  1. Scalar pass: FT_FLAGS / FT_RAW / reserved tags.  Order-
 *     independent so we can run it first without observing the
 *     pointer fields the later passes will populate.
 *  2. Pointer pass: FT_PTR_BYTES / FT_PTR_ARRAY / FT_PTR_STRUCT.
 *     Allocate a sub-buffer via zmalloc_tracked, write the pointer
 *     into the slot, remember the chosen size (bytes for BYTES /
 *     STRUCT, element count for ARRAY) keyed by field index.
 *     Optional pointers may roll NULL+0 with OPTIONAL_PRESENT_PCT
 *     bias toward present, so the NULL-args kernel path keeps
 *     coverage too.
 *  3. Length pass: FT_LEN_BYTES / FT_LEN_COUNT.  Resolve the paired
 *     buffer field by name, read the size/count chosen in pass 2,
 *     write it into the slot at the LEN field's natural width.
 *     Coupled fields stay consistent -- the kernel sees a length
 *     that matches the buffer it describes.
 */
void struct_fill_passes(unsigned char *buf, unsigned int size,
			       const struct struct_field *fields,
			       unsigned int n,
			       struct syscallrecord *rec)
{
	unsigned long chosen_len[STRUCT_FILL_MAX_FIELDS] = {0};
	unsigned int i;

	if (n > STRUCT_FILL_MAX_FIELDS)
		n = STRUCT_FILL_MAX_FIELDS;

	/* Pass 1: scalar tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_PTR_BYTES:
		case FT_PTR_ARRAY:
		case FT_PTR_STRUCT:
		case FT_BPF_PROGRAM:
		case FT_LEN_BYTES:
		case FT_LEN_COUNT:
			continue;	/* deferred to later passes */
		case FT_FLAGS:
			fill_field_flags(buf, f);
			break;
		case FT_EMBEDDED_STRUCT: {
			/*
			 * Cataloged struct embedded in-place at buf + offset.
			 * No allocation, no pointer write -- recursively fill
			 * the target's fields directly into the parent's
			 * backing buffer.  Rec threads through so a nested
			 * variant-carrying descriptor reads the same syscall
			 * args the top-level fill saw.
			 */
			const struct struct_desc *target;

			target = struct_catalog_lookup(
				f->u.embedded_struct.elem_struct_name);
			if (target == NULL || target->struct_size == 0)
				break;
			if (target->struct_size > f->size)
				break;
			struct_field_fill_schema_aware(buf + f->offset,
						       target->struct_size,
						       target, rec);
			break;
		}
		case FT_ADDRESS:
			continue;	/* deferred to pointer pass */
		case FT_FD: {
			/*
			 * Random fd via the generic pool.  Typed-pool draws
			 * (e.g. OBJ_FD_BPF_MAP) are a later lift; today's
			 * fd consumers in the cataloged structs all accept
			 * a generic fd value and the kernel does its own
			 * subtype check.  Sub-int-width FT_FD falls through
			 * to the raw splat since an fd in <4 bytes cannot
			 * round-trip the kernel-side -1 sentinel.
			 */
			int fd;

			if (f->size != sizeof(int)) {
				fill_field_raw(buf, f);
				break;
			}
			fd = get_random_fd();
			write_field_uint(buf, f, (uint64_t)(uint32_t) fd);
			break;
		}
		case FT_ENUM: {
			const unsigned long *vals = f->u.enum_.vals;
			unsigned int nvals = f->u.enum_.n;
			uint64_t v;

			if (vals == NULL || nvals == 0) {
				fill_field_raw(buf, f);
				break;
			}
			v = (uint64_t) vals[rnd_modulo_u32(nvals)];
			write_field_uint(buf, f, v);
			break;
		}
		case FT_VOCAB: {
			const char *const *vocab = f->u.vocab.vocab;
			unsigned int nv = f->u.vocab.vocab_len;
			unsigned int stride = f->u.vocab.element_stride;
			const char *pick;
			size_t plen;

			if (vocab == NULL || nv == 0 || stride == 0) {
				fill_field_raw(buf, f);
				break;
			}
			if (stride > f->size)
				stride = f->size;
			if (stride == 0) {
				fill_field_raw(buf, f);
				break;
			}
			pick = vocab[rnd_modulo_u32(nv)];
			plen = strnlen(pick, stride - 1);
			memset(buf + f->offset, 0, stride);
			memcpy(buf + f->offset, pick, plen);
			break;
		}
		case FT_RANGE: {
			unsigned long lo = f->u.range.lo;
			unsigned long hi = f->u.range.hi;
			uint64_t v;

			if (hi <= lo) {
				fill_field_raw(buf, f);
				break;
			}
			/* Guard against overflow: if hi - lo == ULONG_MAX, hi - lo + 1 wraps to 0 */
			if (hi - lo == ULONG_MAX)
				v = lo + rnd_u64();
			else
				v = lo + rnd_modulo_u64(hi - lo + 1);
			write_field_uint(buf, f, v);
			break;
		}
		case FT_SRANGE: {
			long lo = f->u.srange.lo;
			long hi = f->u.srange.hi;
			uint64_t span;
			int64_t v;

			if (hi <= lo) {
				fill_field_raw(buf, f);
				break;
			}
			span = (uint64_t) hi - (uint64_t) lo + 1;
			v = (int64_t) lo +
			    (int64_t) rnd_modulo_u64(span);
			write_field_uint(buf, f, (uint64_t) v);
			break;
		}
		case FT_MAGIC: {
			const unsigned char *const *vals = f->u.magic.vals;
			unsigned int nv = f->u.magic.n;
			unsigned int stride = f->u.magic.stride;
			const unsigned char *pick;

			if (vals == NULL || nv == 0 ||
			    stride == 0 || stride != f->size) {
				fill_field_raw(buf, f);
				break;
			}
			pick = vals[rnd_modulo_u32(nv)];
			memcpy(buf + f->offset, pick, stride);
			break;
		}
		case FT_PICKER: {
			/*
			 * Delegate to a per-field callback that owns its own
			 * value source (typically a runtime-populated live
			 * pool, e.g. tracepoint ids from tracefs).  The picker
			 * contract -- always return a usable u64, fall back
			 * internally on empty pool -- keeps this case wedge-
			 * free; an unset callback drops to the raw splat so a
			 * partially-initialised FIELDX doesn't silently zero
			 * the slot.
			 */
			if (f->u.picker.pick == NULL) {
				fill_field_raw(buf, f);
				break;
			}
			write_field_uint(buf, f,
					 (uint64_t) f->u.picker.pick());
			break;
		}
		case FT_VERSION_MAGIC:
		case FT_TAGGED_UNION:
		case FT_RAW:
		default:
			fill_field_raw(buf, f);
			break;
		}
	}

	/*
	 * Pre-pin pass: when a LEN field carries a buf_fields[] list
	 * (multi-pair gating, e.g. kprobe_multi's cnt gating
	 * syms+addrs+cookies), roll one shared count and write it into
	 * chosen_len[] for every listed sibling.  Pass 2 then reads
	 * chosen_len[i] for those pointer fields instead of rolling its
	 * own, so all siblings agree on the same count and the LEN
	 * field's value matches every pointer it gates.
	 *
	 * Cap: minimum across the listed siblings' max_count /
	 * max_bytes; absent any cap, the PTR_ARRAY_DEFAULT_MAX default
	 * applies.  All siblings must therefore set a sensible cap or
	 * accept the conservative default.
	 */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		unsigned long count;
		unsigned int cap = 0;
		unsigned int j;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;
		if (f->u.len_of.buf_fields == NULL ||
		    f->u.len_of.n_buf_fields == 0)
			continue;

		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			unsigned int c = 0;

			if (p < 0 || (unsigned int) p >= n)
				continue;
			if (fields[p].tag == FT_PTR_ARRAY)
				c = fields[p].u.ptr_array.max_count;
			else if (fields[p].tag == FT_PTR_BYTES)
				c = fields[p].u.ptr_bytes.max_bytes;
			if (c == 0)
				continue;
			if (cap == 0 || c < cap)
				cap = c;
		}
		if (cap == 0)
			cap = PTR_ARRAY_DEFAULT_MAX;

		count = 1 + rnd_modulo_u32(cap);
		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			if (p < 0 || (unsigned int) p >= n)
				continue;
			chosen_len[p] = count;
		}
	}

	/* Pass 2: pointer tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_PTR_BYTES: {
			unsigned int cap = f->u.ptr_bytes.max_bytes;
			unsigned long nbytes;
			void *sub;

			if (cap == 0)
				cap = PTR_BYTES_DEFAULT_MAX;

			if (f->u.ptr_bytes.optional && !optional_present()) {
				write_field_uint(buf, f, 0);
				break;
			}

			/*
			 * chosen_len[i] != 0 here means a multi-pair LEN
			 * field pre-pinned this buffer's size in the
			 * pin-pass above.  Use the shared value rather
			 * than rolling an independent one.
			 */
			if (chosen_len[i] != 0)
				nbytes = chosen_len[i];
			else
				nbytes = 1 + rnd_modulo_u32(cap);
			sub = zmalloc_tracked(nbytes);
			random_byte_fill(sub, nbytes,
					 f->u.ptr_bytes.null_terminated);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = nbytes;
			break;
		}

		case FT_PTR_ARRAY: {
			unsigned int cap = f->u.ptr_array.max_count;
			const struct struct_desc *elem;
			unsigned int elem_size = 0;
			unsigned long count, nbytes;
			void *sub;

			if (cap == 0)
				cap = PTR_ARRAY_DEFAULT_MAX;

			/*
			 * elem_struct (cataloged struct, size from
			 * struct_size) takes precedence; elem_size
			 * (scalar byte width, e.g. 8 for a u64 array)
			 * is the fallback when no struct is named.  At
			 * least one must resolve to a non-zero width
			 * for the allocation to proceed.
			 */
			elem = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (elem != NULL && elem->struct_size != 0)
				elem_size = elem->struct_size;
			else if (f->u.ptr_array.elem_size != 0)
				elem_size = f->u.ptr_array.elem_size;

			if (elem_size == 0) {
				/*
				 * Neither a cataloged elem_struct nor an
				 * elem_size override: leave NULL.  Paired
				 * LEN field will read chosen_len == 0 and
				 * plant zero, so the (NULL, 0) shape the
				 * kernel sees is internally consistent.
				 */
				write_field_uint(buf, f, 0);
				break;
			}

			if (chosen_len[i] != 0)
				count = chosen_len[i];
			else
				count = 1 + rnd_modulo_u32(cap);
			/*
			 * Clamp count so count * elem_size cannot wrap
			 * size_t: an overflow would size the allocation
			 * from the wrapped result while the fill loop
			 * below still iterated the unwrapped count, writing
			 * past the end of sub and corrupting Trinity's own
			 * heap -- masking or fabricating kernel bugs.
			 */
			if (count > SIZE_MAX / elem_size)
				count = SIZE_MAX / elem_size;
			nbytes = count * elem_size;
			sub = zmalloc_tracked(nbytes);
			deferred_free_enqueue_or_leak(sub);
			/*
			 * Schema-fill each element when a cataloged
			 * elem_struct resolved -- zmalloc_tracked only
			 * zeroes, so a cataloged array would otherwise
			 * reach the kernel as count all-zero structs and
			 * the elem_struct annotation would be silently
			 * inert.  Mirrors the per-buffer fill the single-
			 * pointer FT_PTR_STRUCT case below does.  The
			 * scalar elem_size-override path (elem == NULL or
			 * elem->struct_size == 0) stays zero-filled.
			 */
			if (elem != NULL && elem->struct_size != 0) {
				unsigned long j;

				for (j = 0; j < count; j++)
					struct_field_fill_schema_aware(
						(unsigned char *) sub
							+ j * elem_size,
						elem->struct_size, elem, rec);
			}
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = count;
			break;
		}

		case FT_BPF_PROGRAM: {
#ifdef USE_BPF
			/*
			 * Marker-only tag: allocate a max-tier-sized sub-buffer
			 * and hand it to ebpf_gen_program_into(), which rolls
			 * its own tier (50/25/25 valid/boundary/chaos) and emits
			 * the instruction stream.  prog_type is read from the
			 * sibling "prog_type" field already populated by the
			 * scalar pass; absent or unreadable, default to UNSPEC
			 * so the universal helper set still applies.  chosen_len
			 * carries the generator's actual emit count so the
			 * paired FT_LEN_COUNT writes a matching insn_cnt.
			 */
			const unsigned int max_insns = EBPF_GEN_PROG_MAX_INSNS;
			unsigned int nbytes = max_insns * (unsigned int) sizeof(struct bpf_insn);
			int pt_idx = find_field_index_in(fields, n, "prog_type");
			unsigned int prog_type = 0;
			int out_count = 0;
			void *sub;

			if (pt_idx >= 0 && (unsigned int) pt_idx < n)
				prog_type = (unsigned int)
					read_field_uint(buf, &fields[pt_idx]);

			sub = zmalloc_tracked(nbytes);
			ebpf_gen_program_into(sub, (int) max_insns,
					      &out_count, prog_type);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = (unsigned long) out_count;
#else
			write_field_uint(buf, f, 0);
#endif
			break;
		}

		case FT_PTR_STRUCT: {
			const struct struct_desc *target;
			const struct union_variant *tvariant;
			void *sub;

			if (f->u.ptr_struct.optional && !optional_present()) {
				write_field_uint(buf, f, 0);
				break;
			}

			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (target == NULL || target->struct_size == 0) {
				write_field_uint(buf, f, 0);
				break;
			}

			sub = zmalloc_tracked(target->struct_size);
			struct_field_fill_schema_aware(sub, target->struct_size,
						       target, rec);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			/*
			 * Re-resolve the target's variant now that sub is
			 * populated so the paired length field reports the
			 * per-variant ABI size when one is declared (e.g.
			 * sockaddr_un's 110 vs sockaddr_in's 16).  Falls back
			 * to target->struct_size when no variant resolves or
			 * the variant leaves effective_size at zero.
			 */
			tvariant = struct_desc_resolve_variant(target, rec, sub);
			chosen_len[i] = (tvariant != NULL &&
					 tvariant->effective_size != 0)
					? tvariant->effective_size
					: target->struct_size;
			break;
		}

		case FT_ADDRESS: {
			/*
			 * Plant a get_address() pointer and publish the
			 * companion length so any paired FT_LEN_BYTES field
			 * stays internally consistent.  Length defaults to
			 * page_size when no LEN partner exists -- a NULL
			 * address (~1% via get_address) pins length to 0 so
			 * the (NULL, 0) shape stays coherent for the kernel
			 * sees-NULL-iov-skip arm.
			 */
			void *addr;

			if (f->size != sizeof(unsigned long)) {
				/* sub-pointer-width FT_ADDRESS cannot hold a
				 * useful address; fall back to raw splat. */
				fill_field_raw(buf, f);
				break;
			}
			addr = get_address();
			write_field_uint(buf, f, (uint64_t)(uintptr_t) addr);
			chosen_len[i] = addr ? page_size : 0;
			break;
		}

		default:
			break;
		}
	}

	/* Pass 3: length tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		int paired;

		if (f->offset + f->size > size)
			continue;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;

		/*
		 * Multi-pair: every listed sibling shares the same count
		 * (the pin-pass guaranteed this), so reading from the
		 * first resolvable sibling is sufficient.
		 */
		if (f->u.len_of.buf_fields != NULL) {
			unsigned int j;

			paired = -1;
			for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
				paired = find_field_index_in(fields, n,
					f->u.len_of.buf_fields[j]);
				if (paired >= 0 && (unsigned int) paired < n)
					break;
				paired = -1;
			}
		} else {
			paired = find_field_index_in(fields, n,
						     f->u.len_of.buf_field);
		}
		if (paired < 0 || (unsigned int) paired >= n)
			write_field_uint(buf, f, 0);
		else
			write_field_uint(buf, f, chosen_len[paired]);
	}
}

/*
 * Nested sub-variant overlay: when the outer variant carries a
 * nested_variants table, re-read the sub-discriminator from the
 * just-filled buffer, optionally run the shared base pass, then
 * overlay the matched sub-variant.  Depth-1 only -- the resolver
 * rejects nested-of-nested.  Shared head fields (e.g. link_create's
 * target_btf_id) run once before the specific arm overlays its tail;
 * base is itself a union_variant so the field-fill machinery sees a
 * uniform shape, and we ignore its discrim_value and any (forbidden)
 * nested table.
 */
void struct_variant_overlay_nested(unsigned char *buf, unsigned int size,
					  const struct union_variant *variant,
					  struct syscallrecord *rec)
{
	const struct union_variant *nested;

	if (variant->nested_variants == NULL)
		return;

	nested = struct_desc_resolve_nested_variant(variant, buf, size);
	if (nested == NULL && variant->base == NULL)
		return;

	if (variant->base != NULL)
		struct_fill_passes(buf, size, variant->base->fields,
				   variant->base->num_fields, rec);

	if (nested != NULL)
		struct_fill_passes(buf, size, nested->fields,
				   nested->num_fields, rec);
}
