#pragma once

/*
 * JSON-Lines sink.
 *
 * Minimal open-once / append / close helper for emitting one JSON
 * object per line to a file.  The caller is responsible for producing
 * a valid JSON object string; this layer adds nothing but the trailing
 * newline.
 *
 * Intended for the diag-ring drain and any later per-cmd
 * telemetry that wants a structured on-disk format without pulling in
 * a JSON encoder.  Lives outside trinity's normal output helpers so it
 * can be used before logging/shm/etc. are wired up.
 */

/*
 * Open path for writing.  O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
 * mode 0644.  Returns the new fd on success, -1 on failure with errno
 * set.  The caller must check the return before calling jsonl_write().
 *
 * O_APPEND is load-bearing: the sink is opened in the parent before
 * fork(), so every child inherits the same open file description and
 * shares one write offset.  Without O_APPEND concurrent children race
 * the cursor and interleave or overwrite each other's records.
 */
int jsonl_open(const char *path);

/*
 * Append json_line followed by '\n' to fd.  json_line must already be
 * a complete JSON object; no formatting, escaping, or validation is
 * performed here.
 *
 * Returns 0 on success.  Returns -1 if the writev() call fails (errno
 * set) or produces a short write (partial record, no trailing newline).
 * On failure a best-effort truncation marker is written directly via
 * write() so a downstream reader can distinguish a sink-failure
 * truncation from a clean end-of-run.  The caller is responsible for
 * latching the sink closed and not writing again.
 */
int jsonl_write(int fd, const char *json_line);
