#pragma once

#include <stddef.h>

/*
 * Writable scratch size used for every filesystem-type name buffer.
 * Also the cap gen_fstype_name_pooled() honours internally -- the
 * generated string is always NUL-terminated within FSTYPE_NAME_BUFSZ.
 * 64 bytes leaves ample headroom over the longest filesystem name in
 * /proc/filesystems (~16 chars) while keeping the buffer-cap "long
 * name" bucket comfortably below copy_mount_string()'s PAGE_SIZE cap.
 */
#define FSTYPE_NAME_BUFSZ 64

/*
 * Filesystem-type name generator with a buckets-of-known-paths
 * distribution.  Random bytes virtually never spell out a registered
 * filesystem name, so the mount(2) / fsopen(2) name-resolution path
 * stays cold without a curated pool.  Mix:
 *
 *   40% loaded type (mirrors /proc/filesystems, runtime-varied)
 *   20% always-on builtin pool (deterministic baseline coverage)
 *   20% likely-unloaded autoload pool (request_module path)
 *   10% small random bytes (ENODEV at the name gate)
 *    5% buffer-cap-length filler (long-name copyin path)
 *    5% empty ""
 *
 * Always NUL-terminates within `len`; on len=0 returns without
 * touching the buffer.  Callers size buf at FSTYPE_NAME_BUFSZ.
 */
void gen_fstype_name_pooled(char *buf, size_t len);
