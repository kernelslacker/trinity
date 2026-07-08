#pragma once

/*
 * Wrapper around <linux/android/binder_netlink.h> that ships #ifndef-
 * guarded fallbacks for BINDER_FAMILY_NAME / BINDER_FAMILY_VERSION and
 * every BINDER_A_REPORT_* / BINDER_CMD_* id the grammar references.
 * Build hosts whose installed uapi lacks the header (mainline landed
 * upstream but distro sysroots are lagging) still compile -- the fall-
 * backs carry the file on their own and the family stays registered so
 * runtime CTRL_CMD_GETFAMILY decides whether the loaded kernel exposes
 * "binder".
 *
 * The <linux/android/binder_netlink.h> include is `__has_include`-
 * guarded so a stripped sysroot lacking the header still compiles.
 * Values mirror the upstream YNL-generated uapi enum ordering so the
 * wire-format ids the kernel parses match the ones the message
 * generator emits.
 */
#if __has_include(<linux/android/binder_netlink.h>)
#include <linux/android/binder_netlink.h>
#endif

#ifndef BINDER_FAMILY_NAME
#define BINDER_FAMILY_NAME		"binder"
#endif
#ifndef BINDER_FAMILY_VERSION
#define BINDER_FAMILY_VERSION		1
#endif

#ifndef BINDER_CMD_REPORT
#define BINDER_CMD_REPORT		1
#endif

#ifndef BINDER_A_REPORT_ERROR
#define BINDER_A_REPORT_ERROR		1
#endif
#ifndef BINDER_A_REPORT_CONTEXT
#define BINDER_A_REPORT_CONTEXT		2
#endif
#ifndef BINDER_A_REPORT_FROM_PID
#define BINDER_A_REPORT_FROM_PID	3
#endif
#ifndef BINDER_A_REPORT_FROM_TID
#define BINDER_A_REPORT_FROM_TID	4
#endif
#ifndef BINDER_A_REPORT_TO_PID
#define BINDER_A_REPORT_TO_PID		5
#endif
#ifndef BINDER_A_REPORT_TO_TID
#define BINDER_A_REPORT_TO_TID		6
#endif
#ifndef BINDER_A_REPORT_IS_REPLY
#define BINDER_A_REPORT_IS_REPLY	7
#endif
#ifndef BINDER_A_REPORT_FLAGS
#define BINDER_A_REPORT_FLAGS		8
#endif
#ifndef BINDER_A_REPORT_CODE
#define BINDER_A_REPORT_CODE		9
#endif
#ifndef BINDER_A_REPORT_DATA_SIZE
#define BINDER_A_REPORT_DATA_SIZE	10
#endif
