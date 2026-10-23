/*
 * The pool bookkeeping for a descriptor that a call copying one returned,
 * declared in include/fd.h: pool_dup_result() for a copy of one of ours,
 * pool_foreign_fd() for a copy of another process's.
 */
#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "fd.h"
#include "net.h"
#include "objects.h"
#include "publish_resource.h"

/*
 * Pool the descriptor a successful dup, dup2, dup3 or fcntl(F_DUPFD*)
 * returned under the object type of the one it copies, so it joins the
 * pool its source came from.  A source no pool tracks has no type to
 * inherit, and neither end of the copy may be a descriptor the protected
 * registry shields: the copy reaches the same file.  Types
 * publish_resource() does not route (the pagecache and canary files,
 * scratch block devices) stay unpooled, and the copy stays open.
 *
 * The number is free, or was just closed by dup2/dup3, so a local object
 * still under it names a file that is gone.  Retire it, pooled copy or
 * not, without closing the number: it names the copy now.  Retire before
 * publishing, or the new object goes with it.
 */
void pool_dup_result(int oldfd, int newfd)
{
	enum objecttype type;
	struct object *src;
	struct object *obj;

	if (newfd <= 2 || fd_is_protected(newfd))
		return;

	remove_local_objects_by_fd(newfd);

	if (fd_is_protected(oldfd))
		return;
	src = find_object_by_fd(oldfd);
	if (src == NULL)
		return;

	type = src->obj_type;
	obj = publish_resource(type, newfd, NULL);
	if (obj != NULL && type == OBJ_FD_SOCKET)
		obj->sockinfo.triplet = src->sockinfo.triplet;
}

/*
 * A copy of an fd of another process (pidfd_getfd) has no source in our
 * pools to take a type from, and a pool needs one.  The kernel says, in
 * fstat(), for the two kinds of file whose mode names them: a socket,
 * whose triplet getsockopt() reports, and a pipe end, which end by its
 * access mode.  Every anon-inode file (eventfd, epoll, timerfd, ...)
 * shares one inode, so fstat() cannot tell them apart, and naming them
 * through /proc/self/fd needs a /proc that a fuzzed chroot or mount
 * namespace may have taken away.  Whatever else it is, it is not pooled,
 * and the caller still owns it.
 *
 * A copy on a stdio or protected number is never pooled.  The number is
 * free, so a local object still under it is retired first, pooled or not.
 */
bool pool_foreign_fd(int fd)
{
	static const int sockopts[3] = { SO_DOMAIN, SO_TYPE, SO_PROTOCOL };
	struct socket_triplet triplet;
	unsigned int *const field[3] = {
		&triplet.family, &triplet.type, &triplet.protocol,
	};
	struct object *obj;
	struct stat st;
	int flags, i;

	if (fd <= 2 || fd_is_protected(fd))
		return false;

	remove_local_objects_by_fd(fd);

	if (fstat(fd, &st) != 0)
		return false;

	if (S_ISFIFO(st.st_mode)) {
		flags = fcntl(fd, F_GETFL);
		if (flags < 0)
			return false;
		obj = publish_resource(OBJ_FD_PIPE, fd, NULL);
		if (obj == NULL)
			return false;
		obj->pipeobj.reader = (flags & O_ACCMODE) == O_RDONLY;
		return true;
	}

	if (!S_ISSOCK(st.st_mode))
		return false;

	for (i = 0; i < 3; i++) {
		int val;
		socklen_t len = sizeof(val);

		if (getsockopt(fd, SOL_SOCKET, sockopts[i], &val, &len) != 0 ||
		    len != sizeof(val) || val < 0)
			return false;
		*field[i] = val;
	}
	if (triplet.family >= TRINITY_PF_MAX)
		return false;

	obj = publish_resource(OBJ_FD_SOCKET, fd, NULL);
	if (obj == NULL)
		return false;
	obj->sockinfo.triplet = triplet;
	return true;
}
