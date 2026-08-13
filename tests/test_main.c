/*
 * Test-binary driver.
 *
 * Seeds the RNG from a fixed constant (or -s <seed>) so every run is
 * reproducible, then dispatches to the per-suite entry points.  New
 * suites go in a single call in main() -- the test binary is small
 * enough that a suite registry would be more machinery than the ~10
 * total suite entry points ever need.
 *
 * The seed default is chosen for legibility (0xa17e57 -- "a test"),
 * not for RNG quality; the splitmix64 mix inside rnd_seed() folds any
 * seed into a well-distributed 64-bit state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "rnd.h"
#include "rnd_stream_golden.h"		/* rnd_stream_golden_check */
#include "struct_catalog.h"		/* struct_field_mutate_self_check */

extern pid_t mainpid;
void shared_freelist_self_check(void);
void shared_str_heap_free_size_check(void);
void dispatch_stage_order_self_check(void);
void deferred_free_ownership_self_check(void);
void stats_opclock_lossless_self_check(void);
void struct_field_bounds_self_check(void);

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
	/* Stamp mainpid so shared_str_heap_init()'s parent-only guard
	 * (getpid() == mainpid) is satisfied when the test binary
	 * exercises alloc_shared_str().  Production trinity stamps this
	 * from main() before any fork; the test binary never forks so
	 * the current pid is trivially the mainpid for the whole run. */
	mainpid = getpid();

	printf("trinity test-bin: seed=0x%llx\n",
	       (unsigned long long) seed);

	printf("  struct_field_mutate_self_check ... ");
	fflush(stdout);
	struct_field_mutate_self_check();
	printf("OK\n");

	printf("  rnd_stream_golden_check ... ");
	fflush(stdout);
	rnd_stream_golden_check();
	printf("OK\n");

	printf("  shared_freelist_self_check ... ");
	fflush(stdout);
	shared_freelist_self_check();
	printf("OK\n");

	printf("  shared_str_heap_free_size_check ... ");
	fflush(stdout);
	shared_str_heap_free_size_check();
	printf("OK\n");

	printf("  dispatch_stage_order_self_check ... ");
	fflush(stdout);
	dispatch_stage_order_self_check();
	printf("OK\n");

	printf("  deferred_free_ownership_self_check ... \n");
	fflush(stdout);
	deferred_free_ownership_self_check();
	printf("  deferred_free_ownership_self_check ... OK\n");

	printf("  stats_opclock_lossless_self_check ... ");
	fflush(stdout);
	stats_opclock_lossless_self_check();
	printf("OK\n");

	printf("  struct_field_bounds_self_check ... ");
	fflush(stdout);
	struct_field_bounds_self_check();
	printf("OK\n");

	return 0;
}
