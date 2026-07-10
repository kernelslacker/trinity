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
#include "arch.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
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

/*
 * struct ustat packs an __kernel_daddr_t (int), an __kernel_ino_t
 * (unsigned long on 64-bit), and two char[6] fields; on x86_64 that
 * lays out to 32 bytes after padding.  glibc does not expose the
 * struct, so use a fixed local upper bound for the poison + snapshot
 * window rather than pulling a kernel uapi header against the glibc
 * headers already included above.  32 covers every arch layout the
 * kernel currently defines.
 */
#define USTAT_OUT_SIZE	32

/*
 * Snapshot of the ustat output-buffer pointer + poison seed the post
 * oracle needs, captured at sanitise time.  Lives in rec->post_state,
 * a slot the syscall ABI does not expose, so a sibling syscall
 * scribbling rec->a2 between the syscall returning and the post
 * handler running cannot retarget the untouched-buffer check at a
 * foreign user allocation.  The seed travels with the pointer so a
 * stomp cannot smear the seed against a heap page that happens to
 * still carry a residual pattern from an earlier call.
 */
#define USTAT_POST_STATE_MAGIC	0x55535434UL	/* "UST4" */
struct ustat_post_state {
	unsigned long magic;
	unsigned long ubuf;
	uint64_t poison_seed;
};

static void sanitise_ustat(struct syscallrecord *rec)
{
	struct ustat_post_state *snap;
	void *buf;

	init_ustat_devs();
	rec->a1 = ustat_devs[rnd_modulo_u32(ustat_nr_devs)];

	rec->post_state = 0;

	/*
	 * On a successful lookup the kernel writes a struct ustat (~32B)
	 * into a2.  ARG_NON_NULL_ADDRESS draws from the random pool, so
	 * scrub the writeback target against the alloc_shared regions.
	 * struct ustat is not exposed by glibc, so use a page as an upper
	 * bound on the kernel's writeback window.
	 */
	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * ARG_NON_NULL_ADDRESS draws from get_writable_address(), which
	 * returns NULL when the writable pool cannot back the requested
	 * mapping_sizes[] pick.  Skip the poison + snap install on those
	 * calls -- writing a poison pattern to a NULL or otherwise not-
	 * provably-writable user pointer would SIGSEGV inside the
	 * sanitiser and mask the syscall path we are trying to fuzz.
	 * On skip, rec->post_state stays 0 and post_state_claim_owned()
	 * returns NULL so the post handler no-ops without ever touching
	 * the pointer.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, USTAT_OUT_SIZE))
		return;

	/*
	 * Snapshot the output-buffer pointer + poison seed for the post
	 * oracle.  Without this the post handler reads rec->a2 at post-
	 * time, when a sibling syscall may have scribbled the slot:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user ubuf, so the poison check would
	 * touch a foreign allocation and mistake stale bytes elsewhere
	 * for a real "untouched" signal.  Stamp the poison after
	 * avoid_shared_buffer_out() so it lands on the final buffer the
	 * kernel will see.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = USTAT_POST_STATE_MAGIC;
	snap->ubuf        = rec->a2;
	snap->poison_seed = poison_output_struct(buf, USTAT_OUT_SIZE, 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: ustat(dev, ubuf) writes a struct ustat into user memory on
 * a successful superblock lookup.  Poison the output window at
 * sanitise time and confirm the kernel overwrote the poison on
 * retval=0 -- byte-identical poison after success means the kernel
 * skipped copy_to_user() entirely, or short-copied and left an
 * uninitialised-field tail readable in user memory (a kernel->user
 * infoleak).  Snapshot the buffer via post_snapshot_or_skip so a
 * sibling munmap of the writable-pool page between syscall return
 * and the poison compare degrades to a skipped sample instead of a
 * SIGSEGV in check_output_struct's byte-walk.  Counts against the
 * shared post_handler_untouched_out_buf slot.
 */
static void post_ustat(struct syscallrecord *rec)
{
	struct ustat_post_state *snap;
	unsigned char snapshot[USTAT_OUT_SIZE];

	snap = post_state_claim_owned(rec, USTAT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(snapshot,
				   (void *)(unsigned long) snap->ubuf,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_ustat = {
	.name = "ustat",
	.num_args = 2,
	.argtype = { [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dev", [1] = "ubuf" },
	.sanitise = sanitise_ustat,
	.post = post_ustat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
