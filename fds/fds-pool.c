/*
 * The per-child pool of the files a call hands back that no provider owns,
 * declared in include/fd.h: pool_returned_fd() for any call, pool_open_result()
 * for what a path open may put in it.  The pool's cap lives here, beside
 * pool_typed_fd() for a producer whose result has a type of its own.
 */
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include "child-api.h"
#include "fd.h"
#include "objects.h"
#include "publish_resource.h"

_Static_assert(POOLED_FD_MAX > CHILD_FD_RING_SIZE,
	       "a pooled fd must have left live_fds before it is closed");

/*
 * The pool's oldest object is the one it stamped first.  slot_version counts
 * up per pool, and the array is not in that order: a destroy moves the
 * last slot into the one it empties.
 */
static void destroy_oldest(struct objhead *head)
{
	struct object *oldest = NULL;
	unsigned int i;

	for (i = 0; i < head->num_entries; i++) {
		struct object *obj = head->array[i];

		if (obj == NULL)
			continue;
		if (oldest == NULL ||
		    (int) (obj->slot_version - oldest->slot_version) < 0)
			oldest = obj;
	}
	if (oldest != NULL)
		destroy_object(oldest, OBJ_LOCAL, OBJ_FD_TESTFILE);
}

/*
 * Publish @fd as a local testfile object, the type most open results are
 * (openat and openat2 pin half their paths to the testfiles).  No picker
 * draws from a local file pool by type, so the type only has to name a
 * head whose destructor closes the number: one without a destructor (its
 * provider never ran) cannot close what it owns, and takes nothing.
 *
 * Room is made first, oldest object up, through that destructor and never
 * by a raw close of a number some other object may hold by now.  A pool
 * already past the cap, which the copies a dup makes join without one, is
 * brought back under it; the bound keeps a destroy that leaves its object
 * in place (an inconsistent slot) from looping.
 */
static bool pool_capped(int fd)
{
	struct objhead *head = get_objhead(OBJ_LOCAL, OBJ_FD_TESTFILE);
	unsigned int tries;

	if (head == NULL || head->destroy == NULL)
		return false;

	for (tries = head->num_entries;
	     tries > 0 && head->num_entries >= POOLED_FD_MAX; tries--)
		destroy_oldest(head);

	return publish_resource(OBJ_FD_TESTFILE, fd, NULL) != NULL;
}

/*
 * Pool @fd, which a successful call returned.  The number is a fresh one,
 * so a local object still under it names a file that is gone: retire it,
 * pooled or not, before publishing, or the new object goes with it.
 * stdio and the protected registry's numbers are never pooled, and are not
 * this call's to retire.
 */
bool pool_returned_fd(int fd)
{
	if (fd <= 2 || fd_is_protected(fd))
		return false;

	remove_local_objects_by_fd(fd);

	return pool_capped(fd);
}

/*
 * Pool @fd under @type, the producer's own type, with the same rules as
 * pool_returned_fd() but no cap: these pools are not the open family's
 * shared one.  A head without a destructor would leave @fd with nobody,
 * so a refusal past the stdio and protected check closes it.
 */
struct object *pool_typed_fd(enum objecttype type, int fd)
{
	struct objhead *head;
	struct object *obj = NULL;

	if (fd <= 2 || fd_is_protected(fd))
		return NULL;

	remove_local_objects_by_fd(fd);

	head = get_objhead(OBJ_LOCAL, type);
	if (head != NULL && head->destroy != NULL)
		obj = publish_resource(type, fd, NULL);
	if (obj == NULL)
		close(fd);
	return obj;
}

/*
 * Pool @fd, which an open, openat, openat2, open_by_handle_at or creat
 * returned and @st describes, when it is a regular file or a directory;
 * false leaves it with the caller, who closes it.
 *
 * A device, a FIFO or a socket stays closed.  What a driver does on open or
 * on a later write, and a FIFO that blocks a read, are not bounded by the
 * pathname pools' deny lists, and the providers that hold the device nodes
 * already tag them for what they need.  A regular file can also be another
 * name for a protected one (/proc/self/fd/N reopens the stderr capture),
 * which the registry, knowing numbers, would not shield: refused too.
 */
bool pool_open_result(int fd, const struct stat *st)
{
	if (fd <= 2 || fd_is_protected(fd))
		return false;

	remove_local_objects_by_fd(fd);

	if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode))
		return false;
	if (S_ISREG(st->st_mode) && stat_names_protected_file(st))
		return false;

	return pool_capped(fd);
}
