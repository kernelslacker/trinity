#pragma once

/*
 * Static table of high-value character devices probed at startup.
 *
 * The fd pool normally relies on walking /dev, /proc, and /sys to
 * populate OBJ_FD_DEVFILE / OBJ_FD_PROCFILE / OBJ_FD_SYSFILE, plus
 * the socket-family walker for OBJ_FD_SOCKET.  The walk reliably
 * surfaces regular files and the always-present character devices
 * (/dev/null, /dev/zero, ...), but the high-value subsystem entry
 * points — /dev/kvm, /dev/vfio/vfio, /dev/userfaultfd, /dev/fuse —
 * are gated on kconfig symbols or device-class permissions that the
 * stat-and-open walk silently bounces off, even on a kernel that
 * supports them.
 *
 * dev_template lists each such device with a fixed open flag set and
 * a human-readable gate label; the probe in fds/dev_template.c opens
 * each entry once at startup, publishes the successful opens into
 * OBJ_FD_DEV_TEMPLATE, and logs the gate label for entries that
 * skipped.  Children inherit the fds via fork.
 */
struct dev_template {
	const char *path;
	int flags;
	const char *gate;
};

/*
 * Stable identifier for each table slot, used as the designated
 * initializer index for the static dev_templates[] table.
 */
enum dev_template_id {
	DEV_TEMPLATE_NULL,
	DEV_TEMPLATE_ZERO,
	DEV_TEMPLATE_FULL,
	DEV_TEMPLATE_URANDOM,
	DEV_TEMPLATE_LOOP_CONTROL,
	DEV_TEMPLATE_KVM,
	DEV_TEMPLATE_VFIO,
	DEV_TEMPLATE_TUN,
	DEV_TEMPLATE_USERFAULTFD,
	DEV_TEMPLATE_DRI_RENDER,
	DEV_TEMPLATE_FUSE,
	DEV_TEMPLATE_BTRFS_CONTROL,
	DEV_TEMPLATE_SND_SEQ,
	DEV_TEMPLATE_BINDER,
	DEV_TEMPLATE_MAX
};
