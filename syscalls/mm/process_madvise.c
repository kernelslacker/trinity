/*
 * SYSCALL_DEFINE5(process_madvise, int, pidfd, const struct iovec __user *, vec,
 *                 size_t, vlen, int, behavior, unsigned int, flags)
 *
 * A GUARD_INSTALL acts only on a throwaway mapping of its own, final
 * slots included (vet_final_process_madvise()).
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include "arch.h"
#include "maps.h"
#include "pids.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/mman.h"

/*
 * Full valid set for process_madvise, mirroring madvise_advices[] in
 * madvise.c but excluding MADV_HWPOISON (100) and MADV_SOFT_OFFLINE
 * (101) which are privileged/destructive and out of scope here.
 *
 * On the self path (pidfd resolves to current process) the kernel
 * calls vector_madvise() -> madvise_do_behavior() over the full set.
 * On the remote path (mm != current->mm) the kernel gates the call
 * through process_madvise_remote_valid() and rejects anything outside
 * the four-value remote subset; sanitise_process_madvise() below
 * narrows rec->a4 back to that subset when a non-self pidfd is drawn,
 * so we don't drown the remote path in -EINVAL noise.
 */
static unsigned long process_madvise_behaviours[] = {
	MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED,
	MADV_DONTNEED,
	MADV_FREE, MADV_REMOVE, MADV_DONTFORK, MADV_DOFORK,
	MADV_MERGEABLE, MADV_UNMERGEABLE, MADV_HUGEPAGE, MADV_NOHUGEPAGE,
	MADV_DONTDUMP, MADV_DODUMP,
	MADV_WIPEONFORK, MADV_KEEPONFORK, MADV_COLD, MADV_PAGEOUT,
	MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_DONTNEED_LOCKED, MADV_COLLAPSE,
	MADV_GUARD_INSTALL, MADV_GUARD_REMOVE,
};

/*
 * Remote-only subset: what process_madvise_remote_valid() accepts in
 * the kernel when mm != current->mm.  Used to clamp rec->a4 when a
 * non-self pidfd is drawn so the remote path does not flood -EINVAL.
 */
static unsigned long process_madvise_remote_behaviours[] = {
	MADV_COLD, MADV_PAGEOUT, MADV_WILLNEED, MADV_COLLAPSE,
};

/*
 * flags: the kernel currently requires 0 and returns EINVAL otherwise,
 * but fuzz the non-zero values to keep that gate exercised.
 */
static unsigned long process_madvise_flags[] = {
	0, 0, 0,	/* weight toward the valid path */
	1, 2,
};

/*
 * Return true if the open pidfd fd refers to the calling process.
 * Reads /proc/self/fdinfo/<fd> and parses the kernel-supplied "Pid:"
 * line, which is the tgid of the process the pidfd was opened on.
 * Falls back to returning false (conservative: treat as non-self) on
 * any read or parse error so the caller narrows rather than widens.
 */
static bool pidfd_is_self(int fd)
{
	char path[64], buf[256];
	int info_fd, n;

	if (fd < 0)
		return false;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	info_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (info_fd < 0)
		return false;

	n = read(info_fd, buf, sizeof(buf) - 1);
	close(info_fd);
	if (n <= 0)
		return false;
	buf[n] = '\0';

	/* fdinfo for a pidfd contains a line of the form "Pid:\t<tgid>\n" */
	char *p = strstr(buf, "Pid:");
	if (p == NULL)
		return false;
	p += 4;
	while (*p == ' ' || *p == '\t')
		p++;
	pid_t pid = (pid_t)strtol(p, NULL, 10);
	return pid == mypid();
}

/*
 * The throwaway mapping a self GUARD_INSTALL plants its guards in, for the
 * final-slot hook and the cleanup.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose.
 */
#define PROCESS_MADVISE_POST_STATE_MAGIC	0x504D414456495345UL	/* "PMADVISE" */
struct process_madvise_post_state {
	unsigned long magic;
	unsigned long scratch;
};

/* The pages of that mapping. */
#define PROCESS_MADVISE_SCRATCH_PAGES	4

/*
 * A rewrite after the sanitiser can make any advice a GUARD_INSTALL, or
 * stretch vlen past the iovecs it set, so a final GUARD_INSTALL is refused
 * unless every iovec the kernel reads that names a page
 * (map_range_pages()) names pages of the call's own throwaway mapping.
 * Only an array in the iovec pool can be judged, as nothing but this
 * child writes it; a compat call reads 32-bit iovecs at the low 32 bits
 * of the slot, never an array built here.  A count of 0, or one past
 * UIO_MAXIOV, reads none.  The advice is read as an int.  Shape, then
 * ownership, then magic, as post_state_claim_owned() orders them.
 */
static int vet_final_process_madvise(struct syscallrecord *rec,
				     const struct syscallentry *entry __unused__)
{
	struct process_madvise_post_state *snap =
		(struct process_madvise_post_state *) rec->post_state;
	const struct iovec *iov = (const struct iovec *) rec->a2;
	unsigned long vlen = rec->do32bit ? (unsigned int) rec->a3 : rec->a3;
	unsigned long scratch = 0;
	struct page_span pages;
	unsigned long i;

	if ((int) rec->a4 != MADV_GUARD_INSTALL || vlen == 0 ||
	    vlen > UIO_MAXIOV)
		return 0;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == PROCESS_MADVISE_POST_STATE_MAGIC)
		scratch = snap->scratch;

	if (!rec->do32bit &&
	    range_in_iovec_pool(rec->a2, vlen * sizeof(*iov))) {
		for (i = 0; i < vlen; i++) {
			if (map_range_pages((unsigned long) iov[i].iov_base,
					    iov[i].iov_len, false, false,
					    &pages) &&
			    (scratch == 0 ||
			     !page_span_inside(&pages, scratch,
					PROCESS_MADVISE_SCRATCH_PAGES * page_size)))
				break;
		}
		if (i == vlen)
			return 0;
	}

	outputerr("arg-coupling: process_madvise rejected: the advice installs guard pages\n");
	return -1;
}

/*
 * regular madvise's sanitiser uses range_overlaps_shared() against
 * (rec->a1, rec->a2); process_madvise can't do that because the kernel
 * dereferences vec as an iovec[] rather than treating the addr/len pair
 * as a single range.  Switch the args to ARG_IOVEC/ARG_IOVECLEN so
 * alloc_iovec() runs avoid_shared_buffer() per entry, and walk vec
 * here via the second-pass scrub helper as belt-and-suspenders for the
 * case where avoid_shared_buffer couldn't find a replacement (heap
 * exhausted, len > available) or a sibling scribbled the iovec heap
 * allocation between sanitise and the kernel reading the array.
 *
 * When the drawn pidfd resolves to a foreign process (mm != current->mm)
 * the kernel's process_madvise_remote_valid() gate rejects any advice
 * outside {COLD, PAGEOUT, WILLNEED, COLLAPSE}.  Narrow rec->a4 back to
 * that subset here so the remote path exercises real kernel work rather
 * than returning EINVAL on every call.
 */
static void sanitise_process_madvise(struct syscallrecord *rec)
{
	/*
	 * Clear post_state up front so the final-slot hook and the cleanup
	 * see no snapshot rather than a stale pointer carried over from an
	 * earlier syscall on this record.
	 */
	rec->post_state = 0;

	scrub_iovec_for_kernel_write((struct iovec *)rec->a2, rec->a3);

	if (!pidfd_is_self((int)rec->a1)) {
		rec->a4 = RAND_ARRAY(process_madvise_remote_behaviours);
		return;
	}

	/*
	 * Self-path: MADV_GUARD_INSTALL plants PTE_MARKER_GUARD on every page
	 * in the supplied iovec ranges.  If any of those pages belong to a
	 * trinity pool allocation, the next write from any code path that
	 * reuses the mapping SEGVs the child.  So the call gets a throwaway
	 * mapping of its own: the first iovec names a sub-range of it and
	 * every other iovec's length goes to 0, and the cleanup unmaps it.
	 * With no mapping to be had, every iov_len goes to 0, so the kernel
	 * sees an empty range set and returns at once – the syscall entry
	 * point is still exercised.
	 *
	 * MADV_GUARD_REMOVE is safe to pass through: removing guards from a
	 * range that carries no guard PTEs is a kernel fast-path no-op.
	 *
	 * Mirrors madvise.c's throwaway mapping for the same advice on the
	 * plain madvise(2) path.  The kernel reads the advice as an int, and
	 * vet_final_process_madvise() refuses a GUARD_INSTALL a rewrite makes
	 * later, or one whose iovecs leave the mapping.  A compat call reads
	 * 32-bit iovecs at the low 32 bits of the slot, never the array set
	 * here, so it is handed a count of 0 instead.
	 */
	if ((int) rec->a4 == MADV_GUARD_INSTALL) {
		struct process_madvise_post_state *snap;
		struct iovec *iov = (struct iovec *)rec->a2;
		unsigned long i, vlen = rec->a3, first, pages;
		void *p;

		if (rec->do32bit) {
			rec->a3 = 0;
			return;
		}
		if (iov == NULL)
			return;
		if (vlen > UIO_MAXIOV)
			vlen = UIO_MAXIOV;
		for (i = 0; i < vlen; i++)
			iov[i].iov_len = 0;

		p = mmap(NULL, PROCESS_MADVISE_SCRATCH_PAGES * page_size,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
		if (vlen == 0 || p == MAP_FAILED)
			return;
		first = rnd_modulo_u32(PROCESS_MADVISE_SCRATCH_PAGES);
		pages = 1 + rnd_modulo_u32(PROCESS_MADVISE_SCRATCH_PAGES - first);
		iov[0].iov_base = (char *) p + first * page_size;
		iov[0].iov_len = pages * page_size;

		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic = PROCESS_MADVISE_POST_STATE_MAGIC;
		snap->scratch = (unsigned long) p;
		post_state_install(rec, snap);
	}
}

/* The throwaway mapping goes on every path, and the snapshot with it. */
static void cleanup_process_madvise(struct syscallrecord *rec)
{
	struct process_madvise_post_state *snap;

	snap = post_state_claim_owned(rec, PROCESS_MADVISE_POST_STATE_MAGIC,
				      __func__);
	if (snap != NULL)
		munmap((void *) snap->scratch,
		       PROCESS_MADVISE_SCRATCH_PAGES * page_size);
	post_state_release(rec, snap);
}

struct syscallentry syscall_process_madvise = {
	.name = "process_madvise",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_OP, [4] = ARG_OP },
	.argname = { [0] = "pidfd", [1] = "vec", [2] = "vlen", [3] = "behaviour", [4] = "flags" },
	.arg_params[3].list = ARGLIST(process_madvise_behaviours),
	.arg_params[4].list = ARGLIST(process_madvise_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_process_madvise,
	.vet_final = vet_final_process_madvise,
	.cleanup = cleanup_process_madvise,
	.flags = REEXEC_SANITISE_OK,
	.rettype = RET_NUM_BYTES,
};
