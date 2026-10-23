/*
 * struct_catalog/mount.c -- mount struct field table.
 *
 * Tables are `const` (not `static const`) so the spine's `.fields =`
 * references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU
 * is never empty when USE_<X> is off.
 */

#include <stddef.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/fs.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#include "kernel/mount.h"
/* ------------------------------------------------------------------ */
/* struct mount_attr (mount_setattr, open_tree_attr)                   */
/* ------------------------------------------------------------------ */

#define MOUNT_ATTR_ALL_MASK \
	(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | \
	 MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME | \
	 MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSYMFOLLOW)

/*
 * propagation is effectively a 4-valued enum: do_change_type() EINVALs
 * the moment two propagation bits appear together, so FT_FLAGS would
 * be wrong here -- the mutator would happily OR a second bit in and
 * trip the validator.  FT_ENUM over the four MS_* propagation
 * constants keeps the mutator inside the legal one-bit shape.
 */
static const unsigned long mount_attr_propagation_values[] = {
	MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE,
};

/*
 * mount_setattr / open_tree_attr already carry strong bespoke
 * sanitisers (build_mount_attr() in syscalls/fs/mount/open_tree_attr.c,
 * mirrored by sanitise_mount_setattr) that pick coherent attr_set /
 * attr_clr / propagation / userns_fd buckets and respect the kernel's
 * mutually-exclusive ATIME-mode and propagation rules.  Those sanitisers
 * own rec->a4 (sanitiser_owned_mask), so gen_arg_struct_ptr_in's schema-
 * aware fill never runs for it and the descriptor is read only for the
 * paired size.  The bespoke fill stays live; this entry never displaces
 * it.
 */
const struct struct_field mount_attr_fields[MOUNT_ATTR_FIELDS_N] = {
	FIELDX(struct mount_attr, attr_set, FT_FLAGS,
	       .u.flags.mask = MOUNT_ATTR_ALL_MASK,
	       .mutate_weight = 100),
	FIELDX(struct mount_attr, attr_clr, FT_FLAGS,
	       .u.flags.mask = MOUNT_ATTR_ALL_MASK,
	       .mutate_weight = 80),
	FIELDX(struct mount_attr, propagation, FT_ENUM,
	       .u.enum_ = { mount_attr_propagation_values,
			    ARRAY_SIZE(mount_attr_propagation_values) },
	       .mutate_weight = 80),
	FIELDX(struct mount_attr, userns_fd, FT_FD,
	       .mutate_weight = 60),
};
