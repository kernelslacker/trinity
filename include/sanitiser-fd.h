#pragma once

struct syscallrecord;

/*
 * A descriptor a sanitiser opens for its own call is the child's to close:
 * the sanitiser runs in the child, so nothing else will.  The entry calls
 * sanitiser_own_fd() with the fd it opened (one per dispatch: the record
 * lives in rec->post_state) and sets .cleanup = cleanup_sanitiser_fd, which
 * closes it once the call is done, on every dispatch path.
 *
 * What is closed is the recorded fd, never an arg slot: a slot may hold a
 * pool fd, a sentinel, or a value a chain splice wrote after the sanitiser
 * ran.  A call that recorded nothing closes nothing.
 */
void sanitiser_own_fd(struct syscallrecord *rec, int fd);
void cleanup_sanitiser_fd(struct syscallrecord *rec);
