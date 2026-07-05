/*
 * struct_catalog/landlock.c -- landlock_create_ruleset /
 * landlock_add_rule attr struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <linux/landlock.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct landlock_ruleset_attr (landlock_create_ruleset)              */
/* ------------------------------------------------------------------ */

/*
 * The three fields are u64 bitmasks over disjoint vocab spaces:
 *
 *   handled_access_fs  -> LANDLOCK_ACCESS_FS_*  (bits 0..15)
 *   handled_access_net -> LANDLOCK_ACCESS_NET_* (bits 0..3)
 *   scoped             -> LANDLOCK_SCOPE_*      (bits 0..1)
 *
 * Anything outside its mask makes landlock_create_ruleset return
 * -EINVAL before the ruleset is ever allocated, so an FT_RAW splat
 * almost never reaches security/landlock/ paths.  Mask values are
 * built from the named uapi constants; if a new bit lands upstream
 * the mask needs updating here (caught by reviewer reading uapi diff).
 */
#define LANDLOCK_ACCESS_FS_MASK \
	(LANDLOCK_ACCESS_FS_EXECUTE     | LANDLOCK_ACCESS_FS_WRITE_FILE  | \
	 LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_READ_DIR    | \
	 LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	 LANDLOCK_ACCESS_FS_MAKE_CHAR   | LANDLOCK_ACCESS_FS_MAKE_DIR    | \
	 LANDLOCK_ACCESS_FS_MAKE_REG    | LANDLOCK_ACCESS_FS_MAKE_SOCK   | \
	 LANDLOCK_ACCESS_FS_MAKE_FIFO   | LANDLOCK_ACCESS_FS_MAKE_BLOCK  | \
	 LANDLOCK_ACCESS_FS_MAKE_SYM    | LANDLOCK_ACCESS_FS_REFER       | \
	 LANDLOCK_ACCESS_FS_TRUNCATE    | LANDLOCK_ACCESS_FS_IOCTL_DEV)

/*
 * Linux 7.2 adds UDP bind/connect-send bits to handled_access_net.
 * Older uapi headers don't define them; fall back to the upstream
 * bit assignments so the mask covers the new vocabulary even when
 * built against a stale linux/landlock.h.
 */
#ifndef LANDLOCK_ACCESS_NET_BIND_UDP
#define LANDLOCK_ACCESS_NET_BIND_UDP		(1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
#define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP	(1ULL << 3)
#endif

#define LANDLOCK_ACCESS_NET_MASK					\
	(LANDLOCK_ACCESS_NET_BIND_TCP	  |				\
	 LANDLOCK_ACCESS_NET_CONNECT_TCP  |				\
	 LANDLOCK_ACCESS_NET_BIND_UDP	  |				\
	 LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP)

#define LANDLOCK_SCOPE_MASK \
	(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)

const struct struct_field landlock_ruleset_attr_fields[LANDLOCK_RULESET_ATTR_FIELDS_N] = {
	FIELDX(struct landlock_ruleset_attr, handled_access_fs, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_FS_MASK),
	FIELDX(struct landlock_ruleset_attr, handled_access_net, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_NET_MASK),
	FIELDX(struct landlock_ruleset_attr, scoped, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_SCOPE_MASK),
};

/* ------------------------------------------------------------------ */
/* struct landlock_path_beneath_attr (landlock_add_rule)               */
/* ------------------------------------------------------------------ */

/*
 * landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags) passes
 * the rule_attr struct at a3.  Under LANDLOCK_RULE_PATH_BENEATH the
 * struct is landlock_path_beneath_attr; the bespoke
 * sanitise_landlock_add_rule() in syscalls/landlock_add_rule.c keeps
 * owning the live fill (get_writable_address() allocation, the
 * allowed_access bitmask masked to the low 16 bits, parent_fd drawn
 * from get_random_fd()).  argtype[2] is not declared (the sanitiser
 * unconditionally overwrites rec->a3), so the schema-aware fill path
 * never runs against it -- registration is attribution-only,
 * mirroring sigevent / rseq / landlock_ruleset_attr above.
 *
 * allowed_access carries the LANDLOCK_ACCESS_FS_* vocabulary; reuse
 * the LANDLOCK_ACCESS_FS_MASK defined for landlock_ruleset_attr so a
 * future uapi bit lands in one place.  parent_fd is an open fd the
 * kernel resolves to a path -- no useful per-bit CMP vocab, FT_RAW.
 *
 * The sibling LANDLOCK_RULE_NET_PORT arm passes a different struct
 * (landlock_net_port_attr) at the same a3 slot; that variant is
 * registered separately below and selected by the discriminator-
 * aware syscall_struct_args[] entry on rec->a2 == rule_type.
 */
const struct struct_field landlock_path_beneath_attr_fields[LANDLOCK_PATH_BENEATH_ATTR_FIELDS_N] = {
	FIELDX(struct landlock_path_beneath_attr, allowed_access, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_FS_MASK,
	       .mutate_weight = 80),
	FIELD(struct landlock_path_beneath_attr, parent_fd),
};

/* ------------------------------------------------------------------ */
/* struct landlock_net_port_attr (landlock_add_rule)                   */
/* ------------------------------------------------------------------ */

/*
 * Sibling variant of landlock_path_beneath_attr above: under
 * LANDLOCK_RULE_NET_PORT the rule_attr at a3 is a
 * struct landlock_net_port_attr instead.  The bespoke
 * sanitise_landlock_add_rule() keeps owning the live fill
 * (get_writable_address() allocation, allowed_access drawn from a
 * 2-bit pool covering LANDLOCK_ACCESS_NET_BIND_TCP and
 * LANDLOCK_ACCESS_NET_CONNECT_TCP, port stratified across the
 * ephemeral / well-known / privileged / unprivileged ranges).
 * argtype[2] is not declared, so the schema-aware fill path never
 * runs against rec->a3; registration is attribution-only and mirrors
 * the landlock_path_beneath_attr entry above.
 *
 * allowed_access carries the LANDLOCK_ACCESS_NET_* vocabulary; reuse
 * the LANDLOCK_ACCESS_NET_MASK defined for landlock_ruleset_attr so
 * a future uapi bit lands in one place.  port is __u64 host-endian
 * and the kernel rejects values > 65535 (build_check_abi() bounds);
 * FT_RANGE {0, 65535} steers KCOV-CMP learned constants at the
 * actually-reachable port space.
 *
 * Resolution to this descriptor is gated on the
 * LANDLOCK_RULE_NET_PORT rule_type via the discriminator-aware
 * syscall_struct_args[] entry below, mirroring the fcntl
 * flock / f_owner_ex registration.  Pre-discriminator the catalog
 * could map only one descriptor per (syscall, arg), so a3 resolved
 * to landlock_path_beneath_attr for every rule_type and
 * struct_field_for_cmp() was attributing CMP-learned constants at
 * allowed_access / parent_fd even on NET_PORT dispatches where the
 * kernel was reading a wholly different struct.
 */
const struct struct_field landlock_net_port_attr_fields[LANDLOCK_NET_PORT_ATTR_FIELDS_N] = {
	FIELDX(struct landlock_net_port_attr, allowed_access, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_NET_MASK,
	       .mutate_weight = 80),
	FIELDX(struct landlock_net_port_attr, port, FT_RANGE,
	       .u.range = { 0, 65535 },
	       .mutate_weight = 60),
};
