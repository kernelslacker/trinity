#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "arch.h"	// page_size
#include "debug.h"
#include "random.h"
#include "sanitise.h"	// get_address
#include "maps.h"
#include "log.h"

char *page_rand;

void check_page_rand_redzone(void)
{
	FILE *fd;
	unsigned int i;
	char total = 0;
	char filename[] = "/tmp/trinity-pagerand-XXXXXX";

	for (i = 0; i < page_size; i++)
		total |= page_rand[page_size + i];

	if (total == 0)
		return;

	output(0, "Something stomped the rand page guard page at %p!\n", page_rand + page_size);

	sprintf(filename, "/tmp/trinity-pagerand-%d", getpid());
	fd = fopen(filename, "w");
	if (!fd) {
		perror("Failed to open randpage log");
		return;
	}
	output(0, "Dumped page_rand and guard page to %s\n", filename);

	fwrite(page_rand, page_size, 2, fd);

	fclose(fd);
}

void init_page_rand(void)
{
	page_rand = (char *) memalign(page_size, page_size * 2);
	if (!page_rand)
		exit(EXIT_FAILURE);

	output(2, "page_rand @ %p\n", page_rand);

	memset(page_rand + page_size, 0, page_size);

	generate_random_page(page_rand);
}
