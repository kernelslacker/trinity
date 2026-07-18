/*
 * SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
 *
 * sys_mmap2 (unsigned long addr, unsigned long len, int prot, int flags, int fd, long pgoff)
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "arch.h"
#include "utils.h"
#include "deferred-free.h"
#include "hugepages.h"
#include "objects.h"
#include "random.h"
#include "tables.h"
#include "testfile.h"
#include "trinity.h"

#include "kernel/falloc.h"
#include "kernel/mman.h"
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif

#ifndef MAP_SYNC
#define MAP_SYNC 0x080000
#endif

#ifndef MAP_ABOVE4G
#define MAP_ABOVE4G 0x80
#endif

static void do_anon(struct syscallrecord *rec)
{
	/* no fd if anonymous mapping. */
	rec->a5 = -1;
	rec->a6 = 0;
}

/*
 * Type bits live in the low 2 bits of the mmap flags word: exactly one
 * of MAP_SHARED (0x01), MAP_PRIVATE (0x02), or MAP_SHARED_VALIDATE (0x03).
 * Picking the type is mutually exclusive — never OR these together.
 */
unsigned long mmap_excl_flags[] = {
	MAP_SHARED, MAP_PRIVATE, MAP_SHARED_VALIDATE,
};

unsigned long get_rand_mmap_flags(void)
{
	unsigned long type, flags;

	const unsigned long mmap_flags[] = {
		MAP_FIXED, MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_DENYWRITE,
		MAP_EXECUTABLE, MAP_LOCKED, MAP_NORESERVE, MAP_POPULATE,
		MAP_NONBLOCK, MAP_STACK, MAP_HUGETLB, MAP_UNINITIALIZED,
		MAP_FIXED_NOREPLACE, MAP_DROPPABLE,
#ifdef __x86_64__
		MAP_32BIT,
		MAP_ABOVE4G,
#endif
	};

	type = RAND_ARRAY(mmap_excl_flags);
	flags = type;
	if (RAND_BOOL())
		flags |= set_rand_bitmask(ARRAY_SIZE(mmap_flags), mmap_flags);

	/*
	 * MAP_SYNC is only accepted when the type bit is MAP_SHARED_VALIDATE.
	 * MAP_SHARED|MAP_SYNC returns -EOPNOTSUPP and MAP_PRIVATE|MAP_SYNC
	 * returns -EINVAL, so don't waste calls generating those paths from
	 * the modifier array — gate MAP_SYNC on the picked type.
	 */
	if (type == MAP_SHARED_VALIDATE && RAND_BOOL())
		flags |= MAP_SYNC;

	/*
	 * If MAP_HUGETLB ended up set, sometimes also encode a specific
	 * huge-page size into bits 26..31 via MAP_HUGE_SHIFT.  Without
	 * this the kernel always uses its default size, so MAP_HUGE_2MB,
	 * MAP_HUGE_1GB, etc. never get exercised through the fuzzer.
	 */
	if ((flags & MAP_HUGETLB) && RAND_BOOL())
		flags |= pick_random_huge_size_encoding();

	return flags;
}

static void sanitise_mmap(struct syscallrecord *rec)
{
	/* Don't actually set a hint right now. */
	rec->a1 = 0;

	rec->a2 = RAND_ARRAY(mapping_sizes);

	/* this over-rides the ARG_OP in the syscall struct */
	rec->a4 = get_rand_mmap_flags();

	if (rec->a4 & MAP_ANONYMOUS) {
		do_anon(rec);
	} else {
		rec->a5 = get_random_fd();
		if (rec->a5 == (unsigned long) -1)
			rec->a5 = 0;
		/*
		 * Defer the pgoff rescale until after the shape-overrides
		 * below have settled.  Rescaling here AND in the file-
		 * backed-shared override fired a second divide/mask on
		 * the same value, biasing mmap2 file-backed offsets toward
		 * zero and never exercising the kernel's full-range pgoff
		 * math (sign-extend on 32-bit, pgoff << PAGE_SHIFT overflow,
		 * large-file boundary).
		 */
	}

	/*
	 * The producer pool above is dominated by anonymous
	 * MAP_PRIVATE PROT_READ|PROT_WRITE mappings: get_rand_mmap_flags()
	 * only ORs in modifier bits half the time, and MAP_HUGETLB is one
	 * bit of fourteen in the modifier array.  The vma->vm_flags
	 * variations read by mlock / mlock2 / mprotect / mremap (VM_HUGETLB,
	 * vma->vm_file != NULL, the !readable VM_LOCKED branches in
	 * apply_vma_lock_flags()) therefore almost never land in the pool.
	 * Bias three shapes in at low rates so consumers actually see them.
	 *
	 * Hugetlb and file-backed shared are picked exclusively because
	 * their flag words contradict each other; the PROT_NONE override
	 * below is independent and stacks with either shape.  When the
	 * hugepage pool is empty the mmap returns -ENOMEM; that is the
	 * accepted producer-side cost — the kernel still walks the
	 * MAP_HUGETLB validation paths regardless of the eventual return.
	 */
	if (ONE_IN(8)) {
		rec->a4 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
		if (RAND_BOOL())
			rec->a4 |= pick_random_huge_size_encoding();
		rec->a5 = (unsigned long) -1;
		rec->a6 = 0;
	} else if (ONE_IN(8)) {
		int fd = get_rand_testfile_fd();

		if (fd < 0)
			fd = get_random_fd();
		if (fd >= 0) {
			rec->a4 = MAP_SHARED;
			rec->a5 = (unsigned long) fd;
		}
	}

	/*
	 * MAP_POPULATE / MAP_LOCKED eager-fault the whole VMA inside the
	 * mmap() call.  On a large MAP_ANONYMOUS|MAP_SHARED mapping that is
	 * an instant multi-MB of resident tmpfs-backed shmem, and nothing
	 * prunes these VMAs during the child's life, so a run accumulates
	 * hundreds of MB of shmem per child and can OOM a small box.
	 * Keep the eager-fault coverage on small mappings; drop it above
	 * 2 MB so the large size tiers stay lazy -- their pages become
	 * resident only via the size-capped dirty walk, not all at once.
	 */
	if (rec->a2 > 2UL * 1024 * 1024)
		rec->a4 &= ~(unsigned long)(MAP_POPULATE | MAP_LOCKED);

	/*
	 * rec->a3 is filled from mmap_prots[] via ARG_OP and never lands at
	 * zero, so the !readable VM_LOCKED branches in apply_vma_lock_flags()
	 * (and the analogous reads in apply_mlockall_flags, mprotect_pkey,
	 * mremap_to) are otherwise unreachable.  Force PROT_NONE
	 * occasionally so the pool carries those vma->vm_flags states.
	 */
	if (ONE_IN(8))
		rec->a3 = 0;

	/*
	 * Single pgoff rescale, gated off the final flag word rather
	 * than on a per-branch obligation that future shape-overrides
	 * could forget.  The initial fd-set branch above and the file-
	 * backed-shared override previously each rescaled independently,
	 * doubling the divide/mask when both fired and biasing mmap2
	 * file-backed coverage toward offset 0.  Centralising here makes
	 * the rescale a property of "this call ended up non-anonymous"
	 * regardless of how rec->a4 was arrived at.
	 */
	if (!(rec->a4 & MAP_ANONYMOUS)) {
		if (current_entry_is_mmap2())
			rec->a6 /= page_size;
		else
			rec->a6 &= PAGE_MASK;
	}

	/*
	 * MAP_FIXED unmaps any existing VMA covering [addr, addr + len)
	 * before placing the new mapping there.  If that range overlaps
	 * a trinity-owned shared region — kcov trace_buf, the global
	 * stats blob, child-data, ... — the original VMA is silently
	 * replaced by a (possibly shorter) anon/file mapping.  Reads of
	 * shared bookkeeping past the new mapping's end then SIGBUS.
	 * Drop MAP_FIXED and clear the hint so the kernel picks a free
	 * slot instead.  MAP_FIXED_NOREPLACE returns -EEXIST on overlap
	 * rather than punching, so leave it alone.
	 */
	if ((rec->a4 & MAP_FIXED) &&
	    (RANGE_OVERLAPS_SHARED_AUDITED("mmap", rec->a1, rec->a2) ||
	     range_overlaps_libc_heap(rec->a1, rec->a2))) {
		rec->a4 &= ~MAP_FIXED;
		rec->a1 = 0;
	}

	/*
	 * Diagnostic: pin slips where range_overlaps_libc_heap() passed
	 * the MAP_FIXED addr but a fresh sbrk(0) right here proves it
	 * lies inside the live brk arena.  Pure observability.
	 */
	if (rec->a4 & MAP_FIXED)
		log_mm_syscall_post_gate_heap_slip("mmap", rec->a1, rec->a2,
						   rec->a3);
}

/*
 * Oracle: a successful mmap return must be page-aligned.  A
 * misaligned address indicates the kernel handed back a value
 * that cannot be a real VMA base — feeding it into the object
 * pool would cache a bogus map->ptr that later munmap /
 * mprotect / memory-pressure consumers walk into.
 */
static bool post_mmap_oracle_aligned(char *p)
{
	if ((unsigned long) p & (page_size - 1)) {
		output(0, "mmap oracle: returned addr %p is not page-aligned (page_size=%u)\n",
		       p, page_size);
		__atomic_add_fetch(&shm->stats.oracle.mmap_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		return false;
	}
	return true;
}

/*
 * sanitise_mmap picks rec->a2 from a fixed mapping_sizes[]
 * table without bounding it against the chosen fd's actual
 * file size.  The kernel happily creates a VMA covering pages
 * past EOF, but accessing them SIGBUSes with BUS_ADRERR --
 * dirty_mapping (and later get_map() consumers reading from
 * the OBJ_LOCAL pool entry) walk the recorded size and burn
 * the child before it can contribute to coverage.  Clamp
 * map->size to the in-bounds extent so subsequent walks stay
 * inside real backing.  st_size == 0 on a non-regular file
 * covers /dev/zero, /dev/mem, hugetlb fds, memfd_secret,
 * kcov and any other special fd whose mappable extent is
 * not reflected in stat -- leave the requested size alone
 * for those (they don't SIGBUS the way a short file mmap
 * does).  st_size == 0 on a regular file (a fresh testfile
 * or empty memfd) has no backing at all, so zero map->size
 * to keep the dirty walker off it.  If fstat itself
 * fails (fd was closed or replaced between the syscall and
 * the post handler) the extent is unknown, so zero the size
 * to gate dirty_mapping off rather than walking past EOF.
 */
static void post_mmap_clamp_filebacked(struct object *new, struct syscallrecord *rec)
{
	struct stat st;

	if (rec->a5 != (unsigned long) -1) {
		if (fstat((int) rec->a5, &st) == 0) {
			if (st.st_size > 0) {
				off_t off_bytes = 0;
				bool pgoff_overflows = false;

				/*
				 * sanitise_mmap stores mmap2's pgoff in
				 * page-size units, but the clamp below
				 * works in bytes.  Scale before subtracting
				 * from st_size, otherwise backed is off by
				 * a page_size factor for any mmap2 with
				 * non-zero pgoff.
				 *
				 * rec->a6 is fuzz-controlled and the
				 * multiply can overflow signed off_t.
				 * Reject scales that exceed OFF_T_MAX /
				 * page_size and treat them the same as the
				 * fstat-fails / !S_ISREG && size == 0 arms
				 * below -- zero map.size and bump the
				 * existing clamp stat.
				 */
				if (current_entry_is_mmap2()) {
					unsigned long long off_max =
						(1ULL << (sizeof(off_t) * 8 - 1)) - 1;
					unsigned long max_pgoff =
						(unsigned long) off_max / page_size;

					if (rec->a6 > max_pgoff)
						pgoff_overflows = true;
					else
						off_bytes = (off_t) rec->a6 * (off_t) page_size;
				} else {
					off_bytes = (off_t) rec->a6;
				}

				if (pgoff_overflows) {
					new->map.size = 0;
					__atomic_add_fetch(&shm->stats.mmap_size_clamped,
							   1, __ATOMIC_RELAXED);
				} else {
					off_t backed = (off_t) st.st_size - off_bytes;

					if (backed <= 0)
						new->map.size = 0;
					else if ((unsigned long) backed < new->map.size)
						new->map.size = (unsigned long) backed & PAGE_MASK;

					if (new->map.size != rec->a2)
						__atomic_add_fetch(&shm->stats.mmap_size_clamped,
								   1, __ATOMIC_RELAXED);
				}
			} else if (S_ISREG(st.st_mode)) {
				new->map.size = 0;
				__atomic_add_fetch(&shm->stats.mmap_size_clamped,
						   1, __ATOMIC_RELAXED);
			}
		} else {
			new->map.size = 0;
			__atomic_add_fetch(&shm->stats.mmap_size_clamped,
					   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Sometimes dirty the mapping.
 *
 * Window A: between the post-mmap fstat clamp above (which pinned
 * new->map.size to st_size at allocation time) and this dirty walk,
 * any sibling holding the same fd can ftruncate() it shorter,
 * fallocate(FALLOC_FL_PUNCH_HOLE) it, or fallocate(FALLOC_FL_
 * COLLAPSE_RANGE) it.  Walking the now-stale stored size SIGBUSes
 * BUS_ADRERR on the first page past the new EOF, killing the child
 * before it contributes to coverage (3x ba67bbc7 + 2x 899fc9d9
 * cluster, post_mmap → memcpy SIGBUS).
 *
 * Re-snapshot into a stack-local and re-fstat right before the
 * dirty walk, mirroring dirty_random_mapping (mm/maps.c).  The
 * obj's stored map is left at its post-allocation extent — other
 * consumers (the OBJ_LOCAL pool walker, get_map() readers from
 * later syscalls in this child) reuse that value and may race with
 * us, but mutating it would leak this narrowed view to anyone
 * holding the same handle.
 *
 * fstat failure (EBADF after a sibling close) drops the dirty walk
 * entirely; falling back to the stale stored size is exactly what
 * this clamp exists to avoid.
 */
static void post_mmap_dirty(struct object *new)
{
	if (new->map.size > 0 && RAND_BOOL()) {
		struct map local = new->map;
		bool walk = true;

		if (local.type == MMAPED_FILE && local.fd >= 0) {
			struct stat st2;

			if (fstat(local.fd, &st2) != 0 || st2.st_size == 0) {
				walk = false;
			} else if ((unsigned long) st2.st_size < local.size) {
				local.size = (unsigned long) st2.st_size & PAGE_MASK;
			}
		}

		if (walk && local.size > 0)
			dirty_mapping(&local);
	}
}

/*
 * Oracle: 1-in-100 chance — verify the new mapping is visible in
 * /proc/self/maps with the expected prot bits.  A missing or
 * mismatched entry means the kernel's VMA tree is inconsistent
 * with what it handed back as a successful mmap return address.
 */
static void post_mmap_oracle_proc_maps(char *p, struct syscallrecord *rec)
{
	if (ONE_IN(100)) {
		if (!proc_maps_check((unsigned long) p, rec->a2, rec->a3, true)) {
			output(0, "mmap oracle: mapping at %p size %lu prot 0x%lx "
			       "not visible in /proc/self/maps with expected prot\n",
			       p, rec->a2, rec->a3);
			__atomic_add_fetch(&shm->stats.oracle.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

static void post_mmap(struct syscallrecord *rec)
{
	char *p;
	struct object *new;
	bool is_anon;

	p = (void *) rec->retval;
	if (p == MAP_FAILED)
		return;

	if (!post_mmap_oracle_aligned(p))
		return;

	is_anon = !!(rec->a4 & MAP_ANONYMOUS);

	new = alloc_object();
	new->map.name = strdup("misc");
	if (!new->map.name) {
		tracked_free_now(new);
		return;
	}
	new->map.size = rec->a2;
	/*
	 * map.size is the consumer-walkable extent and gets clamped below
	 * to the file-backed in-bounds region for file-backed mmaps so
	 * dirty walkers stay inside real backing.  map.tracked_size has to
	 * carry the kernel-actual VMA extent (== the length we passed to
	 * mmap()) so map_destructor's tracked_size ?: size fallback and the
	 * sanitise_munmap WHOLE branch unmap the entire VMA, not the
	 * narrowed consumer extent.  Stash it BEFORE any clamp -- the
	 * branch below mutates map.size in place and there is no other
	 * place that holds the pre-clamp length once we are past it.  For
	 * anonymous mappings no clamp fires and size stays equal to
	 * tracked_size; setting it unconditionally documents intent and
	 * keeps the fallback path off the hot teardown lane.  Mirrors
	 * mmap_fd() in mm/maps.c which captures the same field at line
	 * obj->map.tracked_size = len; before its own fstat clamp.
	 */
	new->map.tracked_size = rec->a2;
	new->map.prot = rec->a3;
	/*
	 * Preserve the actual flags word passed to mmap() so map_dump()
	 * and any future flag-aware consumer see the real type bit
	 * (MAP_SHARED / MAP_PRIVATE / MAP_SHARED_VALIDATE) and modifier
	 * bits (MAP_HUGETLB, MAP_SYNC, MAP_STACK, ...).  Without this,
	 * runtime mmap pool entries always reported a zero flags field
	 * and shared/hugetlb mappings looked indistinguishable from
	 * plain private ones in diagnostics.  Mirrors the alloc_zero_map()
	 * pattern in mm/maps-initial.c. */
	new->map.flags = rec->a4;
	new->map.ptr = p;

	if (is_anon) {
		new->map.fd = -1;
		new->map.type = CHILD_ANON;
		add_object(new, OBJ_LOCAL, OBJ_MMAP_ANON);
	} else {
		new->map.fd = rec->a5;
		new->map.type = MMAPED_FILE;

		post_mmap_clamp_filebacked(new, rec);

		add_object(new, OBJ_LOCAL, OBJ_MMAP_FILE);
	}

	post_mmap_dirty(new);

	post_mmap_oracle_proc_maps(p, rec);
}

static char * decode_mmap(struct syscallrecord *rec, unsigned int argnum)
{
	char *buf;

	if (argnum == 3) {
		int flags = rec->a3;
		char *p;
		char *end;

		p = buf = zmalloc(80);
		end = buf + 80;
		p += snprintf(buf, end - p, "[");

		if (flags == 0) {
			snprintf(p, end - p, "PROT_NONE]");
			return buf;
		}
		if (flags & PROT_READ)
			p += snprintf(p, end - p, "PROT_READ|");
		if (flags & PROT_WRITE)
			p += snprintf(p, end - p, "PROT_WRITE|");
		if (flags & PROT_EXEC)
			p += snprintf(p, end - p, "PROT_EXEC|");
		if (flags & PROT_SEM)
			p += snprintf(p, end - p, "PROT_SEM ");
		p--;
		snprintf(p, end - p, "]");

		return buf;
	}
	return NULL;
}

#ifdef __aarch64__
#ifndef PROT_MTE
#define PROT_MTE	0x20		/* aarch64 MTE (5.10+) */
#endif

#ifndef PROT_BTI
#define PROT_BTI	0x10		/* aarch64 BTI */
#endif
#endif

static unsigned long mmap_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
#ifdef __aarch64__
	PROT_MTE, PROT_BTI,
#endif
};

struct syscallentry syscall_mmap = {
	.name = "mmap",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST, [3] = ARG_OP, [4] = ARG_FD, [5] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len", [2] = "prot", [3] = "flags", [4] = "fd", [5] = "off" },
	.arg_params[2].list = ARGLIST(mmap_prots),
	.arg_params[3].list = ARGLIST(mmap_excl_flags),

	.group = GROUP_VM,
	.flags = NEED_ALARM,
	.rettype = RET_ADDRESS,
};

struct syscallentry syscall_mmap2 = {
	.name = "mmap2",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST, [3] = ARG_OP, [4] = ARG_FD, [5] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len", [2] = "prot", [3] = "flags", [4] = "fd", [5] = "pgoff" },
	.arg_params[2].list = ARGLIST(mmap_prots),
	.arg_params[3].list = ARGLIST(mmap_excl_flags),

	.group = GROUP_VM,
	.flags = NEED_ALARM,
	.rettype = RET_ADDRESS,
};
