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
 * Open path for writing.  O_WRONLY | O_CREAT | O_TRUNC, mode 0644.
 * Returns the new fd on success, -1 on failure with errno set.  The
 * caller must check the return before calling jsonl_write().
 */
int jsonl_open(const char *path);

/*
 * Append json_line followed by '\n' to fd.  json_line must already be
 * a complete JSON object; no formatting, escaping, or validation is
 * performed here.  Write errors are swallowed -- the caller is a
 * fuzzer and there is no useful recovery action.
 */
void jsonl_write(int fd, const char *json_line);
