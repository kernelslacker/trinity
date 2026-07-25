/*
 * Test-binary driver.
 *
 * Seeds the RNG from a fixed constant (or -s <seed>) so every run is
 * reproducible, then hands control to the per-suite entry points.
 * Today the suite set is empty: this commit lands the link-graph
 * scaffolding (fake shm + RNG + linker glue) and proves the test
 * binary reaches main() cleanly.  Follow-up commits wire the
 * struct_mutate selftest and the one-child ASAN dry-run path in.
 *
 * The seed default is chosen for legibility (0xa17e57 -- "a test"),
 * not for RNG quality; the splitmix64 mix inside rnd_seed() folds any
 * seed into a well-distributed 64-bit state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rnd.h"

#define DEFAULT_TEST_SEED	0xa17e57ULL

static uint64_t parse_seed(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-s") == 0)
			return strtoull(argv[i + 1], NULL, 0);
	}
	return DEFAULT_TEST_SEED;
}

int main(int argc, char **argv)
{
	uint64_t seed = parse_seed(argc, argv);

	rnd_seed(seed);
	rnd_blob_seed(seed);

	printf("trinity test-bin: seed=0x%llx (scaffolding only)\n",
	       (unsigned long long) seed);
	return 0;
}
