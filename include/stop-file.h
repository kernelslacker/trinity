#pragma once

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Stop request for a run its own uid cannot signal: a non-root parent
 * ignores signals from that uid (parent_stop_reason()).  The parent
 * polls trinity_tmpdir_abs()/STOP_FILE_NAME every main-loop tick.  The
 * '-' keeps the name out of reach of generate_random_pathname().
 */
#define STOP_FILE_NAME	"trinity-stop"

/*
 * A same-uid child can create anything its operator can, so ownership
 * only keeps out other users and, in a root run, the nobody children.
 * lstat(): a symlink is judged by its own owner, not by its target's.
 */
static inline bool stop_file_requested(const char *path, uid_t run_uid)
{
	struct stat st;

	return lstat(path, &st) == 0 &&
	       (st.st_uid == run_uid || st.st_uid == 0);
}
