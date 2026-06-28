#pragma once

/*
 * Wrapper around <linux/target_core_user.h> that ships the
 * #ifndef-guarded fallbacks for the TCMU_CMD_* / TCMU_ATTR_* ids the
 * grammar references.  The .c side includes this from inside its
 * `#if __has_include(<linux/target_core_user.h>)` gate, so the header
 * itself can include <linux/target_core_user.h> unconditionally.
 */
#include <linux/target_core_user.h>

/*
 * Per-symbol shims for TCMU_CMD_* / TCMU_ATTR_* ids.  The TCMU genl
 * uapi has been stable since 4.4; build hosts running older uapi
 * silently miss the *_DONE / SET_FEATURES ids from the validator
 * coverage.  Fallback values match the upstream enum ordering so the
 * wire-format ids the kernel parses match the ones the generator emits.
 */
#ifndef TCMU_CMD_ADDED_DEVICE_DONE
#define TCMU_CMD_ADDED_DEVICE_DONE	4
#endif
#ifndef TCMU_CMD_REMOVED_DEVICE_DONE
#define TCMU_CMD_REMOVED_DEVICE_DONE	5
#endif
#ifndef TCMU_CMD_RECONFIG_DEVICE_DONE
#define TCMU_CMD_RECONFIG_DEVICE_DONE	6
#endif
#ifndef TCMU_CMD_SET_FEATURES
#define TCMU_CMD_SET_FEATURES		7
#endif

#ifndef TCMU_ATTR_DEVICE
#define TCMU_ATTR_DEVICE		1
#endif
#ifndef TCMU_ATTR_MINOR
#define TCMU_ATTR_MINOR			2
#endif
#ifndef TCMU_ATTR_CMD_STATUS
#define TCMU_ATTR_CMD_STATUS		7
#endif
#ifndef TCMU_ATTR_DEVICE_ID
#define TCMU_ATTR_DEVICE_ID		8
#endif
#ifndef TCMU_ATTR_SUPP_KERN_CMD_REPLY
#define TCMU_ATTR_SUPP_KERN_CMD_REPLY	9
#endif
