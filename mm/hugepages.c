/*
 * Helpers for the MAP_HUGE_* / MFD_HUGE_* / SHM_HUGE_* size-encoding
 * bitfield.
 *
 * The kernel packs a 6-bit log2 page-size shift into bits 26..31 of the
 * flags word for mmap(MAP_HUGETLB), memfd_create(MFD_HUGETLB), and
 * shmget(SHM_HUGETLB).  All three syscalls share the same encoding
 * (HUGETLB_FLAG_ENCODE_SHIFT == 26).  These helpers probe
 * /sys/kernel/mm/hugepages/ for the page sizes the host actually
 * supports, plus the transparent-hugepage PMD size and the hugetlbfs
 * pool counts, then hand back a randomly picked shift already moved
 * into the correct bit positions.
 */

#include <dirent.h>
#include <stdio.h>

#include "hugepages.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

#include "kernel/mman.h"
#include "kernel/memfd.h"
#include "kernel/shm.h"
#ifndef HUGETLB_FLAG_ENCODE_SHIFT
#define HUGETLB_FLAG_ENCODE_SHIFT 26
#endif

#define MAX_HUGE_SHIFTS 16

static unsigned int huge_shifts[MAX_HUGE_SHIFTS];
static unsigned int nr_huge_shifts;
static bool huge_shifts_probed;

/*
 * Total hugetlbfs pool for the kernel's default huge page size,
 * including any overcommit budget.  Zero means MAP_HUGETLB is
 * guaranteed to fail with -ENOMEM, so there is no point burning
 * fuzz cycles on picking a specific size encoding.
 */
static unsigned long hugetlb_pool_total;

/*
 * Architecture-agnostic fallback set, used when /sys/kernel/mm/hugepages/
 * is missing (e.g. a stripped-down container).  The kernel will reject
 * any size it doesn't actually support with -EINVAL, which is itself a
 * useful path to fuzz.
 */
static const unsigned int default_huge_shifts[] = {
	21, /* 2MB   */
	25, /* 32MB  */
	28, /* 256MB */
	30, /* 1GB   */
	33, /* 8GB   */
};

static void add_huge_shift(unsigned int shift)
{
	unsigned int i;

	if (nr_huge_shifts == MAX_HUGE_SHIFTS)
		return;
	for (i = 0; i < nr_huge_shifts; i++) {
		if (huge_shifts[i] == shift)
			return;
	}
	huge_shifts[nr_huge_shifts++] = shift;
}

static unsigned long read_ulong_file(const char *path)
{
	FILE *f;
	unsigned long v = 0;

	f = fopen(path, "r");
	if (f == NULL)
		return 0;
	if (fscanf(f, "%lu", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

/*
 * Fold the transparent-hugepage PMD size into the probed set.  THP is
 * a distinct backing mechanism from hugetlbfs, but its PMD size is by
 * definition an architecturally valid huge-page shift, so it is a
 * useful candidate to encode into the MAP_HUGE, MFD_HUGE and SHM_HUGE
 * flag bits even on hosts whose hugetlbfs directory is bare.
 */
static void probe_thp_pmd_size(void)
{
	unsigned long bytes;
	unsigned int shift;

	bytes = read_ulong_file("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size");
	if (bytes == 0 || (bytes & (bytes - 1)) != 0)
		return;

	shift = 0;
	while ((bytes >>= 1) != 0)
		shift++;

	add_huge_shift(shift);
}

static void probe_hugetlb_pool(void)
{
	hugetlb_pool_total = read_ulong_file("/proc/sys/vm/nr_hugepages")
			   + read_ulong_file("/proc/sys/vm/nr_overcommit_hugepages");
}

static void probe_huge_shifts(void)
{
	DIR *d;
	struct dirent *de;
	unsigned int i;

	huge_shifts_probed = true;

	d = opendir("/sys/kernel/mm/hugepages");
	if (d != NULL) {
		while ((de = readdir(d)) != NULL &&
		       nr_huge_shifts < MAX_HUGE_SHIFTS) {
			unsigned long kib;
			unsigned int shift;

			if (sscanf(de->d_name, "hugepages-%lukB", &kib) != 1)
				continue;
			if (kib == 0 || (kib & (kib - 1)) != 0)
				continue;

			/* shift = log2(kib * 1024); start at 10 to fold in the kB. */
			shift = 10;
			while ((kib >>= 1) != 0)
				shift++;

			add_huge_shift(shift);
		}
		closedir(d);
	}

	if (nr_huge_shifts == 0) {
		for (i = 0; i < ARRAY_SIZE(default_huge_shifts); i++)
			add_huge_shift(default_huge_shifts[i]);
	}

	probe_thp_pmd_size();
	probe_hugetlb_pool();
}

unsigned long pick_random_huge_size_encoding(void)
{
	if (!huge_shifts_probed)
		probe_huge_shifts();

	if (nr_huge_shifts == 0)
		return 0;

	/*
	 * With an empty hugetlbfs pool and no overcommit budget, any
	 * MAP_HUGETLB attempt returns -ENOMEM regardless of the picked
	 * shift.  Fall back to encoding nothing so the kernel selects
	 * its default huge page size instead of us cycling through
	 * shifts that we already know will all fail identically.
	 */
	if (hugetlb_pool_total == 0)
		return 0;

	return ((unsigned long) huge_shifts[rnd_modulo_u32(nr_huge_shifts)])
		<< HUGETLB_FLAG_ENCODE_SHIFT;
}
