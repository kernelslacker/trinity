#include <linux/perf_event.h>
#include <sys/stat.h>

#include "bpf.h"
#include "ioctls.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static const struct ioctl perf_event_ioctls[] = {
	IOCTL(PERF_EVENT_IOC_ENABLE),
	IOCTL(PERF_EVENT_IOC_DISABLE),
	IOCTL(PERF_EVENT_IOC_REFRESH),
	IOCTL(PERF_EVENT_IOC_RESET),
	IOCTL(PERF_EVENT_IOC_PERIOD),
	IOCTL(PERF_EVENT_IOC_SET_OUTPUT),
	IOCTL(PERF_EVENT_IOC_SET_FILTER),
	IOCTL(PERF_EVENT_IOC_ID),
	IOCTL(PERF_EVENT_IOC_SET_BPF),
	IOCTL(PERF_EVENT_IOC_PAUSE_OUTPUT),
	IOCTL(PERF_EVENT_IOC_QUERY_BPF),
	IOCTL(PERF_EVENT_IOC_MODIFY_ATTRIBUTES),
};

static int perf_event_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;

	globallist = shm->global_objects[OBJ_FD_PERF].list;
	if (globallist == NULL)
		return -1;

	list_for_each(node, globallist) {
		struct object *obj = (struct object *) node;

		if (obj->perfobj.fd == fd)
			return 0;
	}

	return -1;
}

static void perf_event_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	if (rec->a2 == PERF_EVENT_IOC_SET_BPF || rec->a2 == PERF_EVENT_IOC_QUERY_BPF)
		rec->a3 = (unsigned long) get_rand_bpf_prog_fd();
}

static const struct ioctl_group perf_event_grp = {
	.fd_test = perf_event_fd_test,
	.sanitise = perf_event_sanitise,
	.ioctls = perf_event_ioctls,
	.ioctls_cnt = ARRAY_SIZE(perf_event_ioctls),
};

REG_IOCTL_GROUP(perf_event_grp)
