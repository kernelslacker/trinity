/*
 * SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
 *
 * The kernel runs `dev` through new_decode_dev() and looks up the matching
 * superblock; a random 32-bit value will miss every time and return -EINVAL
 * before the copy_to_user() of ubuf is even reached.  Seed `dev` from the
 * dev_t of paths we know are mounted, encoded the way the kernel decodes.
 */
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "types.h"
#include "utils.h"

static u32 ustat_devs[8];
static unsigned int ustat_nr_devs;

static u32 encode_dev(unsigned int maj, unsigned int min)
{
	/* Inverse of the kernel's new_decode_dev(). */
	return (min & 0xff) | ((maj & 0xfff) << 8) | ((min & ~0xff) << 12);
}

static void add_dev_from_path(const char *path)
{
	struct stat sb;

	if (ustat_nr_devs >= ARRAY_SIZE(ustat_devs))
		return;
	if (stat(path, &sb) != 0)
		return;
	ustat_devs[ustat_nr_devs++] = encode_dev(major(sb.st_dev),
						 minor(sb.st_dev));
}

static void init_ustat_devs(void)
{
	if (ustat_nr_devs > 0)
		return;

	add_dev_from_path("/");
	add_dev_from_path("/proc/self/cwd");
	add_dev_from_path("/tmp");
	add_dev_from_path("/proc");
	add_dev_from_path("/sys");
	add_dev_from_path("/dev");

	/* If nothing stat'd, fall back to plausible majors so we still
	 * exercise the lookup path instead of always EINVAL'ing.
	 */
	if (ustat_nr_devs == 0) {
		ustat_devs[ustat_nr_devs++] = encode_dev(7, 0);   /* loop0 */
		ustat_devs[ustat_nr_devs++] = encode_dev(8, 0);   /* sda */
		ustat_devs[ustat_nr_devs++] = encode_dev(259, 0); /* nvme0n1 */
	}
}

static void sanitise_ustat(struct syscallrecord *rec)
{
	init_ustat_devs();
	rec->a1 = ustat_devs[rand() % ustat_nr_devs];
}

struct syscallentry syscall_ustat = {
	.name = "ustat",
	.num_args = 2,
	.argtype = { [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dev", [1] = "ubuf" },
	.sanitise = sanitise_ustat,
	.group = GROUP_VFS,
};
