/*
 * struct_catalog/mount.c -- mount / namespace struct field tables.
 *
 * Carved out of struct_catalog.c as another leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the mount /
 * namespace leaf data only -- struct mount_attr (mount_setattr /
 * open_tree_attr), struct mnt_id_req (statmount / listmount), and
 * struct ns_id_req (listns).  Symbols flip from static const to const
 * so the spine's .fields = mount_attr_fields / mnt_id_req_fields /
 * ns_id_req_fields references resolve via the externs in
 * struct_catalog-internal.h.
 *
 * The struct ns_id_req fallback below mirrors the trinity-local shim
 * that struct_catalog.c keeps under the same #ifndef NS_ID_REQ_SIZE_VER0
 * guard: the spine references sizeof(struct ns_id_req) on its catalog
 * entry, so the type must stay visible in both TUs.  Both copies must
 * land on a layout-identical definition; a future uapi bump that grows
 * the struct needs both updated.
 *
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty.
 */

#include <stddef.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include "compat.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

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
 * sanitisers (build_mount_attr() in syscalls/open_tree_attr.c, mirrored
 * by sanitise_mount_setattr) that pick coherent attr_set / attr_clr /
 * propagation / userns_fd buckets and respect the kernel's mutually-
 * exclusive ATIME-mode and propagation rules.  Those sanitisers
 * overwrite rec->a4 wholesale after gen_arg_struct_ptr_in's schema-
 * aware fill, so the registration here is attribution-only --
 * struct_field_for_cmp() uses the FT_FLAGS / FT_ENUM / FT_FD tags to
 * steer KCOV-CMP learned constants at the right field rather than at a
 * coincidentally-same-width slot.  The bespoke fill stays live; this
 * entry never displaces it.
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

/* ------------------------------------------------------------------ */
/* struct mnt_id_req (statmount, listmount)                            */
/* ------------------------------------------------------------------ */

const struct struct_field mnt_id_req_fields[MNT_ID_REQ_FIELDS_N] = {
	FIELD(struct mnt_id_req, size),
	FIELD(struct mnt_id_req, mnt_id),
	FIELD(struct mnt_id_req, param),
};

/* ------------------------------------------------------------------ */
/* struct ns_id_req (listns)                                           */
/* ------------------------------------------------------------------ */

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.  Defined locally
 * under the same #ifndef guard the listns sanitiser uses so the
 * translation unit builds against kernel headers that predate the
 * struct.  The shape MUST match the one in syscalls/listns.c -- a
 * future header bump that grows the struct needs both copies updated.
 *
 * ns_type carries a single CLONE_NEW* namespace selector.  An out-of-
 * vocab bit makes listns return -EINVAL before any iterator runs, so
 * an FT_RAW splat almost never reaches the namespace lookup paths;
 * mask the field to the eight defined CLONE_NEW* bits so CMP-learned
 * constants attribute against a real selector.  CLONE_NEWTIME's
 * fallback definition lives in compat.h for older kernel headers.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 ns_type;
	__u64 ns_id;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	24
#endif

#define NS_ID_REQ_NS_TYPE_MASK \
	(CLONE_NEWNS   | CLONE_NEWUTS  | CLONE_NEWIPC     | CLONE_NEWUSER | \
	 CLONE_NEWPID  | CLONE_NEWNET  | CLONE_NEWCGROUP  | CLONE_NEWTIME)

const struct struct_field ns_id_req_fields[NS_ID_REQ_FIELDS_N] = {
	FIELD(struct ns_id_req, size),
	FIELDX(struct ns_id_req, ns_type, FT_FLAGS,
	       .u.flags.mask = NS_ID_REQ_NS_TYPE_MASK),
	FIELD(struct ns_id_req, ns_id),
	FIELD(struct ns_id_req, user_ns_id),
};
