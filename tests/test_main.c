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
void kmsg_trigger_self_check(void);
void pidstat_probe_self_check(void);
void exit_reason_clean_self_check(void);
void parent_stop_self_check(void);
void child_fault_self_check(void);
void stop_file_self_check(void);
void fd_protected_self_check(void);
void owned_fd_ring_self_check(void);
void fd_replenish_self_check(void);
void epoch_reset_self_check(void);
void drop_privs_self_check(void);
void tmpdir_self_check(void);
void reap_stop_self_check(void);
void reap_dead_kids_self_check(void);
void extrafork_reap_self_check(void);
void cmp_field_scan_self_check(void);
void sanitiser_owned_mask_self_check(void);
void minicorpus_abi_self_check(void);
void chain_corpus_self_check(void);
void redqueen_pin_self_check(void);
void asb_relocate_self_check(void);
void loop_status_self_check(void);
void genl_ops_self_check(void);
void kcov_persist_self_check(void);
void shutdown_wait_self_check(void);

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

	printf("  kmsg_trigger_self_check ... ");
	fflush(stdout);
	kmsg_trigger_self_check();
	printf("OK\n");

	printf("  pidstat_probe_self_check ... ");
	fflush(stdout);
	pidstat_probe_self_check();
	printf("OK\n");

	printf("  exit_reason_clean_self_check ... ");
	fflush(stdout);
	exit_reason_clean_self_check();
	printf("OK\n");

	printf("  parent_stop_self_check ... ");
	fflush(stdout);
	parent_stop_self_check();
	printf("OK\n");

	printf("  child_fault_self_check ... ");
	fflush(stdout);
	child_fault_self_check();
	printf("OK\n");

	printf("  stop_file_self_check ... ");
	fflush(stdout);
	stop_file_self_check();
	printf("OK\n");

	printf("  fd_protected_self_check ... ");
	fflush(stdout);
	fd_protected_self_check();
	printf("OK\n");

	printf("  owned_fd_ring_self_check ... ");
	fflush(stdout);
	owned_fd_ring_self_check();
	printf("OK\n");

	printf("  fd_replenish_self_check ... ");
	fflush(stdout);
	fd_replenish_self_check();
	printf("OK\n");

	printf("  epoch_reset_self_check ... ");
	fflush(stdout);
	epoch_reset_self_check();
	printf("OK\n");

	printf("  drop_privs_self_check ... ");
	fflush(stdout);
	drop_privs_self_check();
	printf("OK\n");

	printf("  tmpdir_self_check ... ");
	fflush(stdout);
	tmpdir_self_check();
	printf("OK\n");

	printf("  reap_stop_self_check ... ");
	fflush(stdout);
	reap_stop_self_check();
	printf("OK\n");

	printf("  reap_dead_kids_self_check ... ");
	fflush(stdout);
	reap_dead_kids_self_check();
	printf("OK\n");

	printf("  extrafork_reap_self_check ... ");
	fflush(stdout);
	extrafork_reap_self_check();
	printf("OK\n");

	printf("  cmp_field_scan_self_check ... ");
	fflush(stdout);
	cmp_field_scan_self_check();
	printf("OK\n");

	printf("  sanitiser_owned_mask_self_check ... ");
	fflush(stdout);
	sanitiser_owned_mask_self_check();
	printf("OK\n");

	printf("  minicorpus_abi_self_check ... ");
	fflush(stdout);
	minicorpus_abi_self_check();
	printf("OK\n");

	printf("  chain_corpus_self_check ... ");
	fflush(stdout);
	chain_corpus_self_check();
	printf("OK\n");

	printf("  redqueen_pin_self_check ... ");
	fflush(stdout);
	redqueen_pin_self_check();
	printf("OK\n");

	printf("  asb_relocate_self_check ... ");
	fflush(stdout);
	asb_relocate_self_check();
	printf("OK\n");

	printf("  loop_status_self_check ... ");
	fflush(stdout);
	loop_status_self_check();
	printf("OK\n");

	printf("  genl_ops_self_check ... ");
	fflush(stdout);
	genl_ops_self_check();
	printf("OK\n");

	printf("  kcov_persist_self_check ... ");
	fflush(stdout);
	kcov_persist_self_check();
	printf("OK\n");

	printf("  shutdown_wait_self_check ... ");
	fflush(stdout);
	shutdown_wait_self_check();
	printf("OK\n");

	return 0;
}
