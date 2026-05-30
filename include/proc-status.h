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
 *
 * Only safe for fields whose value width is statically bounded (Uid:, Gid:,
 * Tgid:, Umask:, signal masks, etc.) — the fixed buffer cannot detect
 * truncation, so any field whose size the kernel can grow without warning
 * will silently produce a truncated prefix.  Use proc_status_slurp() for
 * unbounded-width fields such as Groups:.
 */
ssize_t proc_status_read(char *buf, size_t bufsz);

/*
 * Read /proc/self/status into a freshly malloc'd, NUL-terminated heap
 * buffer that grows until the whole file fits.  Returns the buffer on
 * success (caller frees with free()), NULL on open/read/allocation
 * failure.
 *
 * For fields whose value width has no useful static bound: most
 * importantly Groups:, which can carry up to NGROUPS_MAX (65536)
 * supplementary gids as decimal-plus-space tokens — several hundred KB
 * at the limit, well past any reasonable stack buffer.  The fixed-buffer
 * proc_status_read() would silently truncate and hand the parser a
 * prefix; this variant loops with realloc() (doubling from 4 KB) until
 * read(2) returns 0, so the parser always sees the entire file.
 */
char *proc_status_slurp(void);

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

/*
 * Coarse-grained one-call readers built on the primitives above.  Each
 * does open/read/close + newline-anchored field lookup + value parse for
 * a specific field shape so the per-oracle triplet collapses to one call
 * and the buffer-size / slurp-vs-fixed choice lives in one place.
 *
 * proc_status_read_uint_field — single decimal unsigned long (e.g. Pid:,
 *   PPid:).  Uses an 8 KB stack buffer via proc_status_read(); only safe
 *   for fields whose value width is statically bounded.
 *
 * proc_status_read_id_quad — the four-column "real eff saved fs" row
 *   used by Uid: and Gid:.  Same 8 KB stack buffer.  Callers that only
 *   want a subset (e.g. getresuid wants ruid/euid/suid) pick the columns
 *   they need; the unused slot is still parsed.
 *
 * proc_status_read_sigmask — the %016lx signal-mask rows (SigPnd:,
 *   ShdPnd:, SigBlk:, SigIgn:, SigCgt:).  Uses proc_status_slurp()
 *   rather than a fixed buffer because these fields land late enough in
 *   /proc/self/status that a process with a large supplementary group
 *   list or verbose VmFlags can push them past any reasonable stack
 *   buffer — the codex-#3 truncation bug.  Slurp grows on demand so the
 *   bug cannot recur on the migrated callers.
 *
 * All three return false on any failure (open, read, missing field,
 * parse) and leave *out untouched.
 */
bool proc_status_read_uint_field(const char *name, unsigned long *out);
bool proc_status_read_id_quad(const char *name, unsigned long out[4]);
bool proc_status_read_sigmask(const char *name, uint64_t *out);
