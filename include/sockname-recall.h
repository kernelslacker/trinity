#pragma once

struct syscallrecord;

/*
 * The re-call oracle getsockname() and getpeername() share
 * (syscalls/socket/sockname-recall.c).  Both entries take the sanitiser
 * as it is; each call's .post passes the post handler the name its
 * diagnostics carry, the syscall number it re-issues and the counter a
 * divergence bumps.
 */
void sockname_recall_sanitise(struct syscallrecord *rec);
void sockname_recall_post(struct syscallrecord *rec, const char *name,
			  long nr, unsigned long *anomalies);
