#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * /proc/self/status oracle helper.
 *
 * Consolidates the raw open/read/close + newline-anchored field lookup used
 * by syscall post handlers that cross-check a syscall return against the
 * procfs view of the same task field.  No stdio: post handlers run thousands
 * of times per second under fuzz and the per-call FILE/IO buffer churn is
 * heap traffic we don't want.
 */

/*
 * Raw open/read/close of /proc/self/status into buf.  Always NUL-terminates
 * the buffer on success.  Returns bytes read (>0) on success, -1 on any
 * failure (open error, read error, empty read).  bufsz must be >= 2 to leave
 * room for the terminator; calling with bufsz < 2 returns -1.
 */
ssize_t proc_status_read(char *buf, size_t bufsz);

/*
 * Find a named field inside a status buffer previously filled by
 * proc_status_read().  name is the bare field name with no leading newline,
 * no trailing colon (e.g. "Tgid", "Cpus_allowed").  Returns a pointer to the
 * first character after the "<name>:" prefix (i.e. the start of the value,
 * including any leading whitespace the kernel emitted) or NULL if the field
 * is absent.
 *
 * The match always anchors on a preceding newline so that a substring
 * collision with a sibling field cannot mis-target the parse: searching for
 * "Cpus_allowed" returns the Cpus_allowed: row, never Cpus_allowed_list:,
 * and searching for "Uid" cannot land inside a process Name: that happens to
 * contain "Uid".  Callers that need the very first field of the file (Name:)
 * cannot use this helper as-is — none of the current oracles do.
 */
const char *proc_status_find_field(const char *buf, const char *name);

/*
 * Parse a single decimal unsigned long from a field value (the pointer
 * returned by proc_status_find_field).  Used for Tgid:, Pid:, and any other
 * single-number row.  Returns true on success, false if no digits were
 * consumed.
 */
bool proc_status_parse_u(const char *value, unsigned long *out);

/*
 * Parse the four-column "real effective saved fs" row used by Uid: and Gid:.
 * Writes the four values into out[0..3] in order: real, effective, saved, fs.
 * Returns true only if all four columns were parsed.
 */
bool proc_status_parse_uid_gid_quad(const char *value, unsigned long out[4]);

/*
 * Parse a single hex value from a field value, used for the signal-mask rows
 * (SigPnd:, SigBlk:, SigIgn:, SigCgt:) which the kernel formats with
 * %016lx — a single hex word covering all standard signals.  Returns true on
 * success, false if no hex digits were consumed.
 */
bool proc_status_parse_hex_mask(const char *value, uint64_t *out);
