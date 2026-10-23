/*
 * Struct-catalog variant / discriminator resolution: matching a row's
 * discriminator keys against a live syscallrecord (shared with the (nr, arg)
 * lookup in registry.c), and resolving a tagged-union struct_desc, or a
 * variant's nested_variants[], down to the single variant whose discriminator
 * matches.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "trinity.h"

/*
 * Read rec->a<arg_idx> (1-based) into *out.  Returns false when arg_idx
 * is out of range so the caller can skip the variant cleanly.  Folded
 * out so the two key paths (key1 and key2) share the dispatch instead
 * of cloning the six-way switch.
 */
bool read_rec_arg(const struct syscallrecord *rec,
		  unsigned int arg_idx, unsigned long *out)
{
	if (arg_idx == 0 || arg_idx > 6)
		return false;
	switch (arg_idx) {
	case 1: *out = rec->a1; return true;
	case 2: *out = rec->a2; return true;
	case 3: *out = rec->a3; return true;
	case 4: *out = rec->a4; return true;
	case 5: *out = rec->a5; return true;
	case 6: *out = rec->a6; return true;
	}
	return false;
}

/*
 * Match one discriminator key against a raw input value: equal to
 * value, or to any entry of values[] when a list is given.  Folded out
 * so key1 and key2 share the match block.
 */
bool discrim_key_matches(unsigned long raw,
			 unsigned long value,
			 const unsigned long *values,
			 unsigned int num_values)
{
	unsigned int j;

	if (values != NULL) {
		for (j = 0; j < num_values; j++) {
			if (values[j] == raw)
				return true;
		}
		return false;
	}
	return value == raw;
}

/*
 * Pull the entry's key2 value off rec and AND-match it against key1.
 * Returns true when discrim2_arg_idx == 0 (single-key entry: key2 is a
 * no-op) so the caller's single-key AND stays trivially true.  An
 * unreadable second arg (out-of-range) returns false rather than
 * silently passing -- a misconfigured row should not match anything.
 */
bool discrim_key2_matches(const struct syscall_struct_arg *sa,
			  const struct syscallrecord *rec)
{
	unsigned long raw;

	if (sa->discrim2_arg_idx == 0)
		return true;
	if (!read_rec_arg(rec, sa->discrim2_arg_idx, &raw))
		return false;
	return discrim_key_matches(raw, sa->discrim2_value,
				   sa->discrim2_values,
				   sa->num_discrim2_values);
}

/*
 * Read a discriminator of the given width out of buf at off and widen to
 * unsigned long.  Caller must validate width to {1,2,4,8} and that the
 * read stays within the surrounding buffer.
 */
static unsigned long read_discrim(const unsigned char *buf,
				  unsigned int off, unsigned int width)
{
	switch (width) {
	case 1:
		return buf[off];
	case 2: {
		uint16_t v;
		memcpy(&v, buf + off, sizeof(v));
		return v;
	}
	case 4: {
		uint32_t v;
		memcpy(&v, buf + off, sizeof(v));
		return v;
	}
	case 8: {
		uint64_t v;
		memcpy(&v, buf + off, sizeof(v));
		return (unsigned long) v;
	}
	}
	return 0;
}

const struct union_variant *
struct_desc_resolve_variant(const struct struct_desc *desc,
			    struct syscallrecord *rec,
			    const unsigned char *buf)
{
	unsigned long discrim;
	unsigned int idx;
	unsigned int i;

	if (desc == NULL)
		return NULL;
	if (desc->variants == NULL || desc->num_variants == 0)
		return NULL;

	idx = desc->discrim_arg_idx;
	if (idx != 0) {
		if (rec == NULL || idx > 6)
			return NULL;
		switch (idx) {
		case 1: discrim = rec->a1; break;
		case 2: discrim = rec->a2; break;
		case 3: discrim = rec->a3; break;
		case 4: discrim = rec->a4; break;
		case 5: discrim = rec->a5; break;
		case 6: discrim = rec->a6; break;
		default: return NULL;
		}
	} else if (desc->buffer_discrim_size != 0) {
		/*
		 * Buffer-relative discriminator: the just-filled buffer
		 * carries the discriminator value at a fixed offset.
		 * Pre-fill callers pass buf == NULL and short-circuit
		 * here.
		 */
		if (buf == NULL)
			return NULL;
		if (desc->buffer_discrim_offset + desc->buffer_discrim_size >
		    desc->struct_size)
			return NULL;
		/*
		 * Accept widths 1/2/4/8 -- matches the nested reader so the
		 * two callers of read_discrim() stay identical.  Today's
		 * buffer-discrim users are width 2 and 4 only; the width-8
		 * branch is intentionally reachable for future users.
		 */
		if (desc->buffer_discrim_size != 1 &&
		    desc->buffer_discrim_size != 2 &&
		    desc->buffer_discrim_size != 4 &&
		    desc->buffer_discrim_size != 8)
			return NULL;
		discrim = read_discrim(buf, desc->buffer_discrim_offset,
				       desc->buffer_discrim_size);
	} else {
		return NULL;
	}

	for (i = 0; i < desc->num_variants; i++) {
		const struct union_variant *v = &desc->variants[i];

		if (v->discrim_values != NULL) {
			unsigned int j;

			for (j = 0; j < v->num_discrim_values; j++) {
				if (v->discrim_values[j] == discrim)
					return v;
			}
			continue;
		}
		if (v->discrim_value == discrim)
			return v;
	}
	return NULL;
}

const struct union_variant *
struct_desc_resolve_nested_variant(const struct union_variant *outer,
				   const unsigned char *buf,
				   unsigned int size)
{
	unsigned long discrim = 0;
	unsigned int off, width;
	unsigned int i;

	if (outer == NULL || buf == NULL)
		return NULL;
	if (outer->nested_variants == NULL || outer->num_nested_variants == 0)
		return NULL;

	off = outer->nested_discrim_offset;
	width = outer->nested_discrim_size;
	if (width != 1 && width != 2 && width != 4 && width != 8)
		return NULL;
	if (off + width > size)
		return NULL;

	discrim = read_discrim(buf, off, width);

	for (i = 0; i < outer->num_nested_variants; i++) {
		const struct union_variant *v = &outer->nested_variants[i];

		/*
		 * Nested-of-nested is rejected here defensively -- the fill
		 * path also caps recursion, but refusing the entry up-front
		 * keeps the API contract explicit.
		 */
		if (v->nested_variants != NULL)
			continue;

		if (v->discrim_values != NULL) {
			unsigned int j;

			for (j = 0; j < v->num_discrim_values; j++) {
				if (v->discrim_values[j] == discrim)
					return v;
			}
			continue;
		}
		if (v->discrim_value == discrim)
			return v;
	}
	return NULL;
}
