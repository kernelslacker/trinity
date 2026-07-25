/*
 * Test-binary shm provider.
 *
 * PURE modules under test today (args/struct_mutate.c and its
 * struct_catalog/{variant,address}.c helpers) do not reference the
 * shm layer directly, so this TU is a scaffold: it exists so that
 * later Phase-1+ modules migrated onto the arena (whose PURE forms
 * still touch a small subset of shm globals for seed/childno) have
 * a defined home for their fakes without churning the test binary's
 * link line.
 *
 * Fakes go here as symbols are added to the PURE set.  Keep the
 * definitions minimally shaped: a fake shm provider is a scaffold
 * for the test, not a mock of production behaviour, and the goal is
 * "the module links and runs deterministically", not "shm is
 * simulated".  Where a module needs a real shm-derived value
 * (e.g. a child seed), prefer plumbing the value through the test
 * driver in test_main.c over inventing a global here.
 */
