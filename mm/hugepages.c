/*
 * Helpers for the MAP_HUGE_* / MFD_HUGE_* / SHM_HUGE_* size-encoding
 * bitfield.
 *
 * The kernel packs a 6-bit log2 page-size shift into bits 26..31 of the
 * flags word for mmap(MAP_HUGETLB), memfd_create(MFD_HUGETLB), and
 * shmget(SHM_HUGETLB).  All three syscalls share the same encoding
 * (HUGETLB_FLAG_ENCODE_SHIFT == 26).  These helpers probe
 * /sys/kernel/mm/hugepages/ for the page sizes the host actually
 * supports, then hand back a randomly picked shift already moved into
 * the correct bit positions.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "hugepages.h"
#include "random.h"
#include "utils.h"

#ifndef HUGETLB_FLAG_ENCODE_SHIFT
#define HUGETLB_FLAG_ENCODE_SHIFT 26
#endif

#define MAX_HUGE_SHIFTS 16

static unsigned int huge_shifts[MAX_HUGE_SHIFTS];
static unsigned int nr_huge_shifts;
static bool huge_shifts_probed;

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

static void probe_huge_shifts(void)
{
	DIR *d;
	struct dirent *de;
	unsigned int i;

	huge_shifts_probed = true;

	d = opendir("/sys/kernel/mm/hugepages");
	if (d == NULL)
		goto fallback;

	while ((de = readdir(d)) != NULL && nr_huge_shifts < MAX_HUGE_SHIFTS) {
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

		huge_shifts[nr_huge_shifts++] = shift;
	}
	closedir(d);

	if (nr_huge_shifts > 0)
		return;

fallback:
	for (i = 0; i < ARRAY_SIZE(default_huge_shifts); i++)
		huge_shifts[nr_huge_shifts++] = default_huge_shifts[i];
}

unsigned long pick_random_huge_size_encoding(void)
{
	if (!huge_shifts_probed)
		probe_huge_shifts();

	if (nr_huge_shifts == 0)
		return 0;

	return ((unsigned long) huge_shifts[rand() % nr_huge_shifts])
		<< HUGETLB_FLAG_ENCODE_SHIFT;
}
