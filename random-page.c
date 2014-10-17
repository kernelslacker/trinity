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

static void fabricate_onepage_struct(char *page)
{
	unsigned int i;

	for (i = 0; i < page_size; ) {
		void **ptr;

		ptr = (void*)&page[i];

		/* 4 byte (32bit) 8 byte (64bit) alignment */
		if (i & ~((__WORDSIZE / 8) - 1)) {
			unsigned long val;

			i += sizeof(unsigned long);
			if (i > page_size)
				return;

			if (rand_bool())
				val = rand64();
			else
				val = (unsigned long) get_address();

			*(unsigned long *)ptr = val;

		} else {
			/* int alignment */

			i += sizeof(unsigned int);
			if (i > page_size)
				return;

			*(unsigned int *)ptr = rand32();
		}
	}
}

void check_page_rand_redzone(void)
{
	int fd;
	unsigned int i;
	char total = 0;
	char filename[] = "/tmp/trinity-pagerand-XXXXXX";

	for (i = 0; i < page_size; i++)
		total |= page_rand[page_size + i];

	if (total == 0)
		return;

	output(0, "Something stomped the rand page guard page at %p!\n", page_rand + page_size);

	fd = mkstemp(filename);
	if (fd == -1) {
		perror("Failed to mkstemp page_rand log");
		return;
	}
	output(0, "Dumped page_rand and guard page to %s\n", filename);

	if (write(fd, page_rand, page_size * 2) == -1)
		perror("failed to write page_rand log");

	close(fd);
}


void generate_random_page(char *page)
{
	unsigned int i;
	unsigned int p = 0;

	switch (rand() % 8) {

	case 0:
		memset(page, 0, page_size);
		return;

	case 1:
		memset(page, 0xff, page_size);
		return;

	case 2:
		memset(page, rand() % 0xff, page_size);
		return;

	case 3:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand();
		return;

	case 4:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand_bool();
		return;

	/* return a page that looks kinda like a struct */
	case 5:	fabricate_onepage_struct(page);
		return;

	/* page full of format strings. */
	case 6:
		for (i = 0; i < page_size; i += 2) {
			page[i] = '%';
			switch (rand_bool()) {
			case 0:	page[i + 1] = 'd';
				break;
			case 1:	page[i + 1] = 's';
				break;
			}
		}
		page_size = getpagesize();	// Hack for clang 3.3 false positive.
		page[rand() % page_size] = 0;
		return;

	/* ascii representation of a random number */
	case 7:
		switch (rand() % 3) {
		case 0:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%lu", (unsigned long) rand64());
				break;
			case 1:	p = sprintf(page, "%ld", (unsigned long) rand64());
				break;
			case 2:	p = sprintf(page, "%lx", (unsigned long) rand64());
				break;
			}
			break;

		case 1:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%u", (unsigned int) rand32());
				break;
			case 1:	p = sprintf(page, "%d", (int) rand32());
				break;
			case 2:	p = sprintf(page, "%x", (int) rand32());
				break;
			}
			break;

		case 2:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%u", (unsigned char) rand());
				break;
			case 1:	p = sprintf(page, "%d", (char) rand());
				break;
			case 2:	p = sprintf(page, "%x", (char) rand());
				break;
			}
			break;

		}

		page[p] = 0;
		break;
	}
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
