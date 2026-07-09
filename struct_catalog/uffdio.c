/*
 * struct_catalog/uffdio.c -- userfaultfd ioctl argument struct field
 * tables.
 *
 * UFFDIO_* ioctls each carry a fixed-shape struct at the ioctl arg
 * slot; the bespoke sanitisers in ioctls/userfaultfd.c own the live
 * fill (writable-region alloc, mode-bit picker, map-anchored range),
 * so these descriptors are attribution-only: they exist so the
 * schema-aware CMP path can name the specific u64 slot (dst / src /
 * len / mode / features / ...) a KCOV-CMP-learned constant fell out
 * of instead of guessing off width alone.  Ioctl args do not resolve
 * through syscall_struct_args[]; consumers reach these descriptors
 * via struct_catalog_lookup() on the struct name.
 *
 * Tables are `const` (not `static const`) so the spine's designated-
 * init `.fields =` references resolve via the externs in
 * struct_catalog-internal.h.
 */

#include <stddef.h>

#include <linux/userfaultfd.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"

/*
 * struct uffdio_range: the (start, len) tuple shared by UFFDIO_WAKE,
 * UFFDIO_UNREGISTER, and the nested range member of uffdio_register /
 * uffdio_zeropage / uffdio_writeprotect / uffdio_continue / uffdio_
 * poison.  Both fields are u64: `start` is a user-supplied virtual
 * address the kernel walks page tables against, `len` is the byte
 * length of that range.  FT_RAW throughout -- neither field has a
 * paired FT_PTR_ sibling the schema-aware fill would size, so the
 * historical per-field random splat is preserved and struct_field_
 * for_cmp() attributes learned constants by name.
 */
const struct struct_field uffdio_range_fields[UFFDIO_RANGE_FIELDS_N] = {
	FIELD(struct uffdio_range, start),
	FIELD(struct uffdio_range, len),
};

/*
 * struct uffdio_api: the UFFDIO_API handshake payload.  `api` is
 * compared against UFFD_API on the kernel side, `features` is the
 * requested UFFD_FEATURE_* bitmask (kernel intersects with the
 * supported set), and `ioctls` is the kernel-written return bitmap
 * of supported UFFDIO_* opcodes.  All three are u64 and FT_RAW; the
 * bespoke sanitise_uffdio_api() owns the live fill of api/features
 * (with UFFD_API pinned most of the time) and zeros ioctls before
 * dispatch.
 */
const struct struct_field uffdio_api_fields[UFFDIO_API_FIELDS_N] = {
	FIELD(struct uffdio_api, api),
	FIELD(struct uffdio_api, features),
	FIELD(struct uffdio_api, ioctls),
};

/*
 * struct uffdio_register: UFFDIO_REGISTER payload.  `range` is the
 * embedded (start, len) sub-struct, `mode` is the UFFDIO_REGISTER_
 * MODE_* bitmask (MISSING / WP / MINOR), and `ioctls` is the kernel-
 * written return bitmap of per-mode supported opcodes.  All FT_RAW;
 * range is left as a single 16-byte slot rather than enumerated
 * flat -- struct_field_for_cmp() attributes u64 CMP constants at
 * mode / ioctls (size 8) and skips the 16-byte range slot naturally.
 */
const struct struct_field uffdio_register_fields[UFFDIO_REGISTER_FIELDS_N] = {
	FIELD(struct uffdio_register, range),
	FIELD(struct uffdio_register, mode),
	FIELD(struct uffdio_register, ioctls),
};

/*
 * struct uffdio_copy: UFFDIO_COPY payload.  `dst` and `src` are user
 * virtual addresses, `len` is the byte length copied, `mode` is the
 * UFFDIO_COPY_MODE_* bitmask (DONTWAKE / WP), and `copy` is the
 * kernel-written signed return count (negative on error).  All FT_RAW;
 * the bespoke sanitise_uffdio_copy() pins dst / src to live map
 * anchors and picks mode from the DONTWAKE|WP pool.
 */
const struct struct_field uffdio_copy_fields[UFFDIO_COPY_FIELDS_N] = {
	FIELD(struct uffdio_copy, dst),
	FIELD(struct uffdio_copy, src),
	FIELD(struct uffdio_copy, len),
	FIELD(struct uffdio_copy, mode),
	FIELD(struct uffdio_copy, copy),
};

/*
 * struct uffdio_zeropage: UFFDIO_ZEROPAGE payload.  `range` is the
 * embedded (start, len) sub-struct, `mode` is the UFFDIO_ZEROPAGE_
 * MODE_DONTWAKE bit, and `zeropage` is the kernel-written signed
 * return count.  All FT_RAW; sanitise_uffdio_zeropage() pins range
 * to a live map anchor and toggles the DONTWAKE mode bit half the
 * time.
 */
const struct struct_field uffdio_zeropage_fields[UFFDIO_ZEROPAGE_FIELDS_N] = {
	FIELD(struct uffdio_zeropage, range),
	FIELD(struct uffdio_zeropage, mode),
	FIELD(struct uffdio_zeropage, zeropage),
};
