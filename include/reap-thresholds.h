/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _REAP_THRESHOLDS_H
#define _REAP_THRESHOLDS_H

/*
 * REAP_STALL_THRESHOLD_S - wall-clock seconds of zero progress after which
 * the parent watchdog (main/reap-watchdog.c) sends SIGKILL to a stuck child.
 *
 * Kept in a dedicated header so that:
 *  - main/reap-watchdog.c (the authoritative kill site) and
 *  - include/userns-bootstrap.h (which derives its alarm ceilings from it)
 * both see the same token.  _Static_assert in userns-bootstrap.h then
 * cross-checks USERNS_PARENT_ALARM_S < REAP_STALL_THRESHOLD_S in every TU
 * that includes that header -- drift between the two sites is impossible.
 */
#define REAP_STALL_THRESHOLD_S  30u

#endif /* _REAP_THRESHOLDS_H */
