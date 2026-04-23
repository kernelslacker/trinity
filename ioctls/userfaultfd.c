/* userfaultfd ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/userfaultfd.h>

#include "ioctls.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static int userfaultfd_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = &shm->global_objects[OBJ_FD_USERFAULTFD];

	for_each_obj(head, obj, idx) {
		if (obj->userfaultobj.fd == fd)
			return 0;
	}

	return -1;
}

static void sanitise_uffdio_api(struct syscallrecord *rec)
{
	struct uffdio_api *ua;
	static const unsigned long api_features[] = {
		UFFD_FEATURE_PAGEFAULT_FLAG_WP,
		UFFD_FEATURE_EVENT_FORK,
		UFFD_FEATURE_EVENT_REMAP,
		UFFD_FEATURE_EVENT_REMOVE,
		UFFD_FEATURE_EVENT_UNMAP,
		UFFD_FEATURE_MISSING_HUGETLBFS,
		UFFD_FEATURE_MISSING_SHMEM,
		UFFD_FEATURE_SIGBUS,
		UFFD_FEATURE_THREAD_ID,
		UFFD_FEATURE_MINOR_HUGETLBFS,
		UFFD_FEATURE_MINOR_SHMEM,
		UFFD_FEATURE_EXACT_ADDRESS,
		UFFD_FEATURE_WP_HUGETLBFS_SHMEM,
		UFFD_FEATURE_WP_UNPOPULATED,
		UFFD_FEATURE_POISON,
		UFFD_FEATURE_WP_ASYNC,
		UFFD_FEATURE_MOVE,
	};

	ua = (struct uffdio_api *) get_writable_struct(sizeof(*ua));
	if (!ua)
		return;
	/* Most of the time perform a real handshake (api == UFFD_API)
	 * so any subsequent ioctl on this fd has a chance of succeeding.
	 * Occasionally fuzz the api number to exercise the reject path. */
	ua->api = ONE_IN(20) ? (__u64) rand64() : UFFD_API;
	ua->features = set_rand_bitmask(ARRAY_SIZE(api_features), api_features);
	ua->ioctls = 0;
	rec->a3 = (unsigned long) ua;
}

static void sanitise_uffdio_register(struct syscallrecord *rec)
{
	struct uffdio_register *ur;
	struct map *map;
	static const unsigned long register_modes[] = {
		UFFDIO_REGISTER_MODE_MISSING,
		UFFDIO_REGISTER_MODE_WP,
		UFFDIO_REGISTER_MODE_MINOR,
	};

	ur = (struct uffdio_register *) get_writable_struct(sizeof(*ur));
	if (!ur)
		return;
	map = get_map();
	if (map) {
		ur->range.start = (unsigned long) map->ptr;
		ur->range.len = map->size;
	}
	ur->mode = set_rand_bitmask(ARRAY_SIZE(register_modes), register_modes);
	rec->a3 = (unsigned long) ur;
}

static void sanitise_uffdio_copy(struct syscallrecord *rec)
{
	struct uffdio_copy *uc;
	struct map *map;
	static const unsigned long copy_modes[] = {
		UFFDIO_COPY_MODE_DONTWAKE,
		UFFDIO_COPY_MODE_WP,
	};

	uc = (struct uffdio_copy *) get_writable_struct(sizeof(*uc));
	if (!uc)
		return;
	map = get_map();
	if (map) {
		uc->dst = (unsigned long) map->ptr;
		uc->len = map->size;
	}
	map = get_map();
	if (!map)
		return;
	uc->src = (unsigned long) map->ptr;
	uc->mode = set_rand_bitmask(ARRAY_SIZE(copy_modes), copy_modes);
	rec->a3 = (unsigned long) uc;
}

static void sanitise_uffdio_zeropage(struct syscallrecord *rec)
{
	struct uffdio_zeropage *uz;
	struct map *map;

	uz = (struct uffdio_zeropage *) get_writable_struct(sizeof(*uz));
	if (!uz)
		return;
	map = get_map();
	if (map) {
		uz->range.start = (unsigned long) map->ptr;
		uz->range.len = map->size;
	}
	uz->mode = RAND_BOOL() ? UFFDIO_ZEROPAGE_MODE_DONTWAKE : 0;
	rec->a3 = (unsigned long) uz;
}

static void sanitise_uffdio_writeprotect(struct syscallrecord *rec)
{
	struct uffdio_writeprotect *uwp;
	struct map *map;
	static const unsigned long wp_modes[] = {
		UFFDIO_WRITEPROTECT_MODE_WP,
		UFFDIO_WRITEPROTECT_MODE_DONTWAKE,
	};

	uwp = (struct uffdio_writeprotect *) get_writable_struct(sizeof(*uwp));
	if (!uwp)
		return;
	map = get_map();
	if (map) {
		uwp->range.start = (unsigned long) map->ptr;
		uwp->range.len = map->size;
	}
	uwp->mode = set_rand_bitmask(ARRAY_SIZE(wp_modes), wp_modes);
	rec->a3 = (unsigned long) uwp;
}

static void sanitise_uffdio_continue(struct syscallrecord *rec)
{
	struct uffdio_continue *uc;
	struct map *map;
	static const unsigned long continue_modes[] = {
		UFFDIO_CONTINUE_MODE_DONTWAKE,
		UFFDIO_CONTINUE_MODE_WP,
	};

	uc = (struct uffdio_continue *) get_writable_struct(sizeof(*uc));
	if (!uc)
		return;
	map = get_map();
	if (map) {
		uc->range.start = (unsigned long) map->ptr;
		uc->range.len = map->size;
	}
	uc->mode = set_rand_bitmask(ARRAY_SIZE(continue_modes), continue_modes);
	rec->a3 = (unsigned long) uc;
}

static void sanitise_uffdio_poison(struct syscallrecord *rec)
{
	struct uffdio_poison *up;
	struct map *map;

	up = (struct uffdio_poison *) get_writable_struct(sizeof(*up));
	if (!up)
		return;
	map = get_map();
	if (map) {
		up->range.start = (unsigned long) map->ptr;
		up->range.len = map->size;
	}
	up->mode = RAND_BOOL() ? UFFDIO_POISON_MODE_DONTWAKE : 0;
	rec->a3 = (unsigned long) up;
}

static void sanitise_uffdio_move(struct syscallrecord *rec)
{
	struct uffdio_move *um;
	struct map *map;
	static const unsigned long move_modes[] = {
		UFFDIO_MOVE_MODE_DONTWAKE,
		UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES,
	};

	um = (struct uffdio_move *) get_writable_struct(sizeof(*um));
	if (!um)
		return;
	map = get_map();
	if (map) {
		um->dst = (unsigned long) map->ptr;
		um->len = map->size;
	}
	map = get_map();
	if (!map)
		return;
	um->src = (unsigned long) map->ptr;
	um->mode = set_rand_bitmask(ARRAY_SIZE(move_modes), move_modes);
	rec->a3 = (unsigned long) um;
}

static void userfaultfd_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case UFFDIO_API:
		sanitise_uffdio_api(rec);
		break;
	case UFFDIO_REGISTER:
		sanitise_uffdio_register(rec);
		break;
	case UFFDIO_COPY:
		sanitise_uffdio_copy(rec);
		break;
	case UFFDIO_ZEROPAGE:
		sanitise_uffdio_zeropage(rec);
		break;
	case UFFDIO_WRITEPROTECT:
		sanitise_uffdio_writeprotect(rec);
		break;
	case UFFDIO_CONTINUE:
		sanitise_uffdio_continue(rec);
		break;
	case UFFDIO_POISON:
		sanitise_uffdio_poison(rec);
		break;
	case UFFDIO_MOVE:
		sanitise_uffdio_move(rec);
		break;
	default:
		break;
	}
}

static const struct ioctl userfaultfd_ioctls[] = {
	IOCTL(UFFDIO_API),
	IOCTL(UFFDIO_REGISTER),
	IOCTL(UFFDIO_UNREGISTER),
	IOCTL(UFFDIO_WAKE),
	IOCTL(UFFDIO_COPY),
	IOCTL(UFFDIO_ZEROPAGE),
	IOCTL(UFFDIO_WRITEPROTECT),
	IOCTL(UFFDIO_CONTINUE),
	IOCTL(UFFDIO_POISON),
	IOCTL(UFFDIO_MOVE),
};

static const struct ioctl_group userfaultfd_grp = {
	.name = "userfaultfd",
	.fd_test = userfaultfd_fd_test,
	.sanitise = userfaultfd_sanitise,
	.ioctls = userfaultfd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(userfaultfd_ioctls),
};

REG_IOCTL_GROUP(userfaultfd_grp)
