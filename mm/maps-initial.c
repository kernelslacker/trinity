/*
 * These routines create initial mmaps in the main process that every
 * child process will end up inheriting.
 *
 * Children will copy the whole initial_mappings list to their own
 * private copies, and then perform operations upon them.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "compat.h"
#include "maps.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

static void alloc_zero_map(unsigned long size, int prot, int flags, const char *name)
{
	struct object *new;

	if (size == 0)
		return;

	new = alloc_shared_obj(sizeof(struct object));
	if (new == NULL) {
		outputerr("alloc_shared_obj failure for OBJ_MMAP_ANON\n");
		exit(EXIT_FAILURE);
	}
	new->map.size = size;
	new->map.prot = prot;
	new->map.flags = flags;
	new->map.fd = -1;
	new->map.type = INITIAL_ANON;
	new->map.ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | flags, -1, 0);
	if (new->map.ptr == MAP_FAILED) {
		outputerr("mmap failure:%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	track_shared_region((unsigned long)new->map.ptr, size);

	new->map.name = alloc_shared_str(80);
	if (new->map.name == NULL) {
		outputerr("alloc_shared_str failure for OBJ_MMAP_ANON name\n");
		exit(EXIT_FAILURE);
	}
	snprintf(new->map.name, 80, "anon(%s)", name);

	add_object(new, OBJ_GLOBAL, OBJ_MMAP_ANON);
}

/*
 * Like alloc_zero_map, but returns false instead of exiting on mmap failure.
 * Used for MAP_HUGETLB mappings which may not be available.
 */
static bool try_alloc_zero_map(unsigned long size, int prot, int flags, const char *name)
{
	struct object *new;

	if (size == 0)
		return false;

	new = alloc_shared_obj(sizeof(struct object));
	if (new == NULL)
		return false;
	new->map.size = size;
	new->map.prot = prot;
	new->map.flags = flags;
	new->map.fd = -1;
	new->map.type = INITIAL_ANON;
	new->map.ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | flags, -1, 0);
	if (new->map.ptr == MAP_FAILED) {
		free_shared_obj(new, sizeof(struct object));
		return false;
	}
	track_shared_region((unsigned long)new->map.ptr, size);

	new->map.name = alloc_shared_str(80);
	if (new->map.name == NULL) {
		munmap(new->map.ptr, new->map.size);
		free_shared_obj(new, sizeof(struct object));
		return false;
	}
	snprintf(new->map.name, 80, "anon(%s)", name);
	add_object(new, OBJ_GLOBAL, OBJ_MMAP_ANON);

	return true;
}

unsigned long mapping_sizes[NR_MAPPING_SIZES] = {
	-1,	/* over-written with page_size below */
	64UL * 1024, 256UL * 1024,
	MB(1), MB(2),
	MB(4), MB(16), MB(64),
	GB(1),
};

static unsigned long long get_free_mem(void)
{
	FILE *fp;
	char *buffer = NULL;
	size_t n = 0;
	unsigned long long memfree = 0;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return 0;

	while (getline(&buffer, &n, fp) >= 0) {
		if (sscanf(buffer, "MemFree:         %llu", &memfree) == 1) {
			break;
		}
	}
	free(buffer);
	fclose(fp);

	return memfree;
}

static void setup_mapping_sizes(void)
{
	unsigned long long memfree;

	mapping_sizes[0] = page_size;

	/* Using 1GB mappings ends up oom'ing a lot, so we don't
	 * want to do it every single run.  It's worth doing it
	 * occasionally though, to stress the oom paths.
	 */
	if (!ONE_IN(100))
		goto disable_1gb_mappings;

	memfree = get_free_mem();
	if (memfree == 0) {
		// Something is really fucked. Let's not try big mappings just in case.
		goto disable_1gb_mappings;
	}

	if ((memfree * 1024) < GB(8ULL)) {
		output(0, "Free memory: %.2fGB\n", (double) memfree / 1024 / 1024);
		output(0, "Low on memory, disabling mmaping of 1GB pages\n");
		goto disable_1gb_mappings;
	}


	// Because of increased mem usage, don't do nr_cpus * 4
	if (max_children > 4) {
		output(0, "Limiting children from %u to %u\n",
				max_children, max_children / 4);
		max_children /= 4;
		return;
	}
	return;

disable_1gb_mappings:
	mapping_sizes[8] = page_size;
}

void setup_initial_mappings(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_MMAP_ANON);
	head->destroy = &map_destructor_shared;
	head->dump = &map_dump;
	head->shared_alloc = true;

	setup_mapping_sizes();

	for (i = 0; i < ARRAY_SIZE(mapping_sizes); i++) {
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE, MAP_SHARED, "PROT_READ | PROT_WRITE");
		alloc_zero_map(mapping_sizes[i], PROT_READ, MAP_SHARED, "PROT_READ");
		alloc_zero_map(mapping_sizes[i], PROT_WRITE, MAP_SHARED, "PROT_WRITE");
		alloc_zero_map(mapping_sizes[i], PROT_EXEC, MAP_SHARED, "PROT_EXEC");
		alloc_zero_map(mapping_sizes[i], PROT_NONE, MAP_SHARED, "PROT_NONE");
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_EXEC, MAP_SHARED, "PROT_READ | PROT_EXEC");
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, "PROT_READ | PROT_WRITE | PROT_EXEC");
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE, MAP_PRIVATE, "PROT_READ | PROT_WRITE (private)");
		alloc_zero_map(mapping_sizes[i], PROT_READ, MAP_PRIVATE, "PROT_READ (private)");
		alloc_zero_map(mapping_sizes[i], PROT_WRITE, MAP_PRIVATE, "PROT_WRITE (private)");
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, "PROT_READ | PROT_WRITE | PROT_EXEC (private)");
	}

	/*
	 * Try to create MAP_HUGETLB mappings.  These exercise the hugetlb
	 * page fault and VMA paths.  We only use 2MB-aligned sizes since
	 * that's the default huge page size on x86.  Failures are expected
	 * when huge pages aren't configured or available.
	 */
	if (try_alloc_zero_map(MB(2), PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_HUGETLB,
			       "PROT_READ | PROT_WRITE (hugetlb shared)"))
		output(0, "Created 2MB MAP_HUGETLB shared mapping\n");

	if (try_alloc_zero_map(MB(2), PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_HUGETLB,
			       "PROT_READ | PROT_WRITE (hugetlb private)"))
		output(0, "Created 2MB MAP_HUGETLB private mapping\n");

	if (try_alloc_zero_map(MB(2), PROT_READ,
			       MAP_SHARED | MAP_HUGETLB,
			       "PROT_READ (hugetlb shared)"))
		output(0, "Created 2MB MAP_HUGETLB read-only mapping\n");
}
