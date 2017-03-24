/*
 * These routines create initial mmaps in the main process that every
 * child process will end up inheriting.
 *
 * Children will copy the whole initial_mappings list to their own
 * private copies, and then perform operations upon them.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "list.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct object *new;
	int fd;

	if (size == 0)
		return;

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		outputerr("couldn't open /dev/zero\n");
		exit(EXIT_FAILURE);
	}

	new = alloc_object();
	new->map.size = size;
	new->map.prot = prot;
	new->map.type = INITIAL_ANON;
	new->map.ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_SHARED, fd, 0);
	if (new->map.ptr == MAP_FAILED) {
		outputerr("mmap failure:%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	new->map.name = zmalloc(80);

	sprintf(new->map.name, "anon(%s)", name);

	add_object(new, OBJ_GLOBAL, OBJ_MMAP_ANON);

	close(fd);
}

unsigned long mapping_sizes[NR_MAPPING_SIZES] = {
	-1,	/* over-written with page_size below */
	MB(1), MB(2),
	GB(1),
};

static unsigned long long get_free_mem(void)
{
	FILE *fp;
	char *buffer;
	size_t n = 0;
	unsigned long long memfree = 0;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return 0;

	buffer = malloc(4096);
	if (!buffer)
		goto out_close;

	while (getline(&buffer, &n, fp) >= 0) {
		if (sscanf(buffer, "MemFree:         %llu", &memfree) == 1) {
			goto done;
		}
	}
done:
	free(buffer);
out_close:
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
	if (!(ONE_IN(100)))
		goto disable_1gb_mappings;

	memfree = get_free_mem();
	if (memfree == 0) {
		// Something is really fucked. Let's not try big mappings just in case.
		goto disable_1gb_mappings;
	}

	if ((memfree * 1024) < GB(8ULL)) {
		printf("Free memory: %.2fGB\n", (double) memfree / 1024 / 1024);
		printf("Low on memory, disabling mmaping of 1GB pages\n");
		goto disable_1gb_mappings;
	}


	// Because of increased mem usage, don't do nr_cpus * 4
	if (max_children > 4) {
		printf("Limiting children from %u to %u\n",
				max_children, max_children / 4);
		max_children /= 4;
		return;
	}

disable_1gb_mappings:
	mapping_sizes[3] = page_size;
}

void setup_initial_mappings(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_MMAP_ANON);
	head->destroy = &map_destructor;
	head->dump = &map_dump;

	setup_mapping_sizes();

	for (i = 0; i < ARRAY_SIZE(mapping_sizes); i++) {
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
		alloc_zero_map(mapping_sizes[i], PROT_READ, "PROT_READ");
		alloc_zero_map(mapping_sizes[i], PROT_WRITE, "PROT_WRITE");
	}
}
