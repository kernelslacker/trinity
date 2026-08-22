/* userfaultfd ioctl fuzzing */

#include <linux/ioctl.h>

#include "kernel/userfaultfd.h"

#include "ioctls.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/*
 * Compile-time: every fixed-shape UFFDIO_* command the sanitisers
 * below fill must have sizeof(struct) matching the _IOC_SIZE encoded
 * in its request bits.  A mismatch means <linux/userfaultfd.h> moved
 * under us and the sanitiser is memset()ing / stamping into a buffer
 * the kernel copies less of than we prepared (under-encoded) or
 * reads past (over-encoded).  UFFDIO_WAKE and UFFDIO_UNREGISTER both
 * take struct uffdio_range and each get their own assert -- the two
 * sides can drift independently in a header refactor.
 */
IOCTL_SIZE_ASSERT(UFFDIO_API, struct uffdio_api);
IOCTL_SIZE_ASSERT(UFFDIO_REGISTER, struct uffdio_register);
IOCTL_SIZE_ASSERT(UFFDIO_UNREGISTER, struct uffdio_range);
IOCTL_SIZE_ASSERT(UFFDIO_WAKE, struct uffdio_range);
IOCTL_SIZE_ASSERT(UFFDIO_COPY, struct uffdio_copy);
IOCTL_SIZE_ASSERT(UFFDIO_ZEROPAGE, struct uffdio_zeropage);
IOCTL_SIZE_ASSERT(UFFDIO_WRITEPROTECT, struct uffdio_writeprotect);
IOCTL_SIZE_ASSERT(UFFDIO_CONTINUE, struct uffdio_continue);
IOCTL_SIZE_ASSERT(UFFDIO_POISON, struct uffdio_poison);
IOCTL_SIZE_ASSERT(UFFDIO_MOVE, struct uffdio_move);
IOCTL_SIZE_ASSERT(UFFDIO_RWPROTECT, struct uffdio_rwprotect);
IOCTL_SIZE_ASSERT(UFFDIO_SET_MODE, struct uffdio_set_mode);

static int userfaultfd_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_USERFAULTFD);

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
		/*
		 * EVENT_* features omitted on purpose: they block the triggering
		 * mm op until a monitor read()s the event, and trinity runs no
		 * uffd monitor (see fds/userfaultfd.c arm_userfaultfd()).
		 */
		UFFD_FEATURE_PAGEFAULT_FLAG_WP,
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
		/*
		 * RWP and RWP_ASYNC gate UFFDIO_REGISTER_MODE_RWP and the
		 * UFFDIO_SET_MODE toggle respectively; without them in the
		 * handshake the kernel rejects both at registration and the
		 * new commands are unreachable.  RWP_ASYNC is the one that
		 * resolves faults in-kernel with no message to a monitor,
		 * which is precisely why it is safe to negotiate here: the
		 * EVENT_* features are excluded above because they block the
		 * triggering op until a monitor reads, and trinity runs no
		 * monitor.  Async is the opposite -- it needs no reader.
		 */
		UFFD_FEATURE_RWP,
		UFFD_FEATURE_RWP_ASYNC,
	};

	ua = (struct uffdio_api *) get_writable_struct(sizeof(*ua));
	if (!ua)
		return;
	memset(ua, 0, sizeof(*ua));
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
		UFFDIO_REGISTER_MODE_RWP,
	};

	ur = (struct uffdio_register *) get_writable_struct(sizeof(*ur));
	if (!ur)
		return;
	memset(ur, 0, sizeof(*ur));
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
	memset(uc, 0, sizeof(*uc));
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
	memset(uz, 0, sizeof(*uz));
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
	memset(uwp, 0, sizeof(*uwp));
	map = get_map();
	if (map) {
		uwp->range.start = (unsigned long) map->ptr;
		uwp->range.len = map->size;
	}
	uwp->mode = set_rand_bitmask(ARRAY_SIZE(wp_modes), wp_modes);
	rec->a3 = (unsigned long) uwp;
}

/*
 * UFFDIO_RWPROTECT -- same shape as UFFDIO_WRITEPROTECT, different
 * meaning: !MODE_RWP undoes the protection rather than applying it, so
 * a bitmask draw covers both the protect and the un-protect direction
 * against a range that may or may not be registered for RWP.
 */
static void sanitise_uffdio_rwprotect(struct syscallrecord *rec)
{
	struct uffdio_rwprotect *urwp;
	struct map *map;
	static const unsigned long rwp_modes[] = {
		UFFDIO_RWPROTECT_MODE_RWP,
		UFFDIO_RWPROTECT_MODE_DONTWAKE,
	};

	urwp = (struct uffdio_rwprotect *) get_writable_struct(sizeof(*urwp));
	if (!urwp)
		return;
	memset(urwp, 0, sizeof(*urwp));
	map = get_map();
	if (map) {
		urwp->range.start = (unsigned long) map->ptr;
		urwp->range.len = map->size;
	}
	urwp->mode = set_rand_bitmask(ARRAY_SIZE(rwp_modes), rwp_modes);
	rec->a3 = (unsigned long) urwp;
}

/*
 * UFFDIO_SET_MODE -- runtime feature toggle, and the only uffd command
 * with a documented cross-field rule: "setting a bit in both enable and
 * disable is invalid".  A hand-written mutual-exclusion check on a live
 * toggle is worth hitting from both sides, so a third of the draws set
 * the SAME bit in both words to aim straight at it, and the rest pick
 * the two words independently -- which lands on the invalid overlap
 * only by chance, and on the legal enable-or-disable paths the rest of
 * the time.
 *
 * UFFD_FEATURE_RWP_ASYNC is the only feature the kernel accepts here
 * today; drawing values outside that set keeps the reject arm live for
 * whatever gets added next.
 */
static void sanitise_uffdio_set_mode(struct syscallrecord *rec)
{
	struct uffdio_set_mode *usm;
	static const unsigned long toggle_features[] = {
		UFFD_FEATURE_RWP_ASYNC,
		UFFD_FEATURE_RWP,
		UFFD_FEATURE_WP_ASYNC,
		UFFD_FEATURE_POISON,
	};

	usm = (struct uffdio_set_mode *) get_writable_struct(sizeof(*usm));
	if (!usm)
		return;
	memset(usm, 0, sizeof(*usm));

	if (ONE_IN(3)) {
		/* Aim at the both-set-is-invalid rule deliberately. */
		usm->enable = set_rand_bitmask(ARRAY_SIZE(toggle_features),
					       toggle_features);
		usm->disable = usm->enable;
	} else {
		usm->enable = set_rand_bitmask(ARRAY_SIZE(toggle_features),
					       toggle_features);
		usm->disable = set_rand_bitmask(ARRAY_SIZE(toggle_features),
						toggle_features);
	}
	rec->a3 = (unsigned long) usm;
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
	memset(uc, 0, sizeof(*uc));
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
	memset(up, 0, sizeof(*up));
	map = get_map();
	if (map) {
		up->range.start = (unsigned long) map->ptr;
		up->range.len = map->size;
	}
	up->mode = RAND_BOOL() ? UFFDIO_POISON_MODE_DONTWAKE : 0;
	rec->a3 = (unsigned long) up;
}

static void sanitise_uffdio_range(struct syscallrecord *rec)
{
	struct uffdio_range *range;
	struct map *map;

	range = (struct uffdio_range *) get_writable_struct(sizeof(*range));
	if (!range)
		return;
	memset(range, 0, sizeof(*range));
	map = get_map();
	if (map) {
		range->start = (unsigned long) map->ptr;
		range->len = map->size;
	}
	rec->a3 = (unsigned long) range;
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
	memset(um, 0, sizeof(*um));
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
	case UFFDIO_RWPROTECT:
		sanitise_uffdio_rwprotect(rec);
		break;
	case UFFDIO_SET_MODE:
		sanitise_uffdio_set_mode(rec);
		break;
	case UFFDIO_WAKE:
	case UFFDIO_UNREGISTER:
		sanitise_uffdio_range(rec);
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
	IOCTL(UFFDIO_RWPROTECT),
	IOCTL(UFFDIO_SET_MODE),
};

static const struct ioctl_group userfaultfd_grp = {
	.name = "userfaultfd",
	.fd_test = userfaultfd_fd_test,
	.sanitise = userfaultfd_sanitise,
	.ioctls = userfaultfd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(userfaultfd_ioctls),
};

REG_IOCTL_GROUP(userfaultfd_grp)
