/*
 * Self-check for setup_initial_mappings() (mm/maps-initial.c): the one run
 * in a hundred that draws the 1 GiB row must still start under the
 * RLIMIT_AS cap init_rlimits() sets before it, where one 1 GiB mapping per
 * kind cannot fit.  A forked child caps its address space 8 GiB above what
 * it already maps (ASAN's shadow alone is terabytes) and builds the pool.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_get_objhead, fake_{alloc,add}_object */
#include "maps.h"		/* setup_initial_mappings */
#include "objects.h"
#include "random.h"		/* ONE_IN */
#include "rnd.h"		/* rnd_seed */
#include "utils.h"		/* waitpid_eintr, GB */
#include "utils-mem.h"		/* alloc_shared_str, free_shared_str */

static struct objhead anon_head;

static struct objhead *anon_pool(enum obj_scope scope, enum objecttype type)
{
	if (scope != OBJ_GLOBAL || type != OBJ_MMAP_ANON)
		BUG("maps_initial: a pool other than the global anon one was asked for");
	return &anon_head;
}

static struct object *calloc_object(void)
{
	return calloc(1, sizeof(struct object));
}

/* The pool's contents are not under test, only that building it returns. */
static void drop_object(struct object *obj, enum obj_scope scope,
			enum objecttype type)
{
	(void) obj;
	(void) scope;
	(void) type;
}

static unsigned long vm_size_bytes(void)
{
	char line[128];
	unsigned long kb = 0;
	FILE *f = fopen("/proc/self/status", "r");

	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL)
		if (sscanf(line, "VmSize: %lu kB", &kb) == 1)
			break;
	fclose(f);
	return kb * 1024;
}

static void __attribute__((noreturn)) build_pool_under_as_cap(void)
{
	struct rlimit rl;
	unsigned long vm = vm_size_bytes();
	uint64_t s;

	if (vm == 0 || getrlimit(RLIMIT_AS, &rl) != 0)
		_exit(2);
	rl.rlim_cur = vm + GB(8UL);
	if (rl.rlim_max != RLIM_INFINITY && rl.rlim_cur > rl.rlim_max)
		rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_AS, &rl) != 0)
		_exit(2);

	fake_get_objhead = anon_pool;
	fake_alloc_object = calloc_object;
	fake_add_object = drop_object;

	/* setup_mapping_sizes() takes the first draw: make it the 1 GiB row. */
	for (s = 1; ; s++) {
		rnd_seed(s);
		if (ONE_IN(100))
			break;
	}
	rnd_seed(s);

	setup_initial_mappings();
	_exit(0);
}

void maps_initial_self_check(void);
void maps_initial_self_check(void)
{
	int status;
	pid_t pid;

	/* The shared string heap is set up by the parent only; the child's
	 * map names come from it. */
	free_shared_str(alloc_shared_str(1));

	pid = fork();
	if (pid < 0)
		BUG("maps_initial: fork failed");
	if (pid == 0)
		build_pool_under_as_cap();

	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("maps_initial: waitpid failed");
	if (WIFEXITED(status) && WEXITSTATUS(status) == 2)
		BUG("maps_initial: could not cap the child's address space");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		BUG("maps_initial: setup_initial_mappings() did not return under an RLIMIT_AS cap");
}
