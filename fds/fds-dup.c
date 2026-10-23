/*
 * pool_dup_result(): the pool bookkeeping shared by the calls that copy a
 * descriptor, declared in include/fd.h.
 */
#include "fd.h"
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
