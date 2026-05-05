#pragma once

/*
 * MAP_HUGE_*, MFD_HUGE_*, and SHM_HUGE_* all encode a log2 page-size
 * shift into the upper 6 bits of their flags arg via the same
 * HUGETLB_FLAG_ENCODE_SHIFT (26) layout.  pick_random_huge_size_encoding()
 * picks a random shift from the host-supported set and returns it pre-
 * shifted, ready to OR into the appropriate *_HUGETLB-bearing flags word.
 * Returns 0 when no sizes are known, meaning "use the kernel's default
 * huge page size".
 */
unsigned long pick_random_huge_size_encoding(void);
