/*
 * Executable-file pool: absolute paths of real executables for the
 * uprobe_multi path fill.
 */

#pragma once

/* One random executable path from the pool, or NULL when the pool
 * is empty (no scannable bin directory and no usable fallback). */
const char *exec_path_pick(void);

/* Pool introspection for the bpf_gen self-check: how many paths the
 * pool holds, and the path at an index (NULL past the end). */
unsigned int exec_paths_count(void);
const char *exec_path_at(unsigned int i);
