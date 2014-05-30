#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "arch.h"	// page_size
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

void generate_random_page(char *page)
{
	unsigned int i;
	unsigned int p = 0;

	switch (rand() % 11) {

	case 0:
		memset(page, 0, page_size);
		return;

	case 1:
		memset(page, 0xff, page_size);
		return;

	case 2:
		memset(page, rand() % 0xff, page_size);
		return;

	/* return a page of complete trash */
	case 3:	/* bytes */
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand();
		return;

	case 4:	/* words */
		for (i = 0; i < (page_size / 2); ) {
			page[i++] = 0;
			page[i++] = (unsigned char)rand();
		}
		return;

	case 5:	/* ints */
		for (i = 0; i < (page_size / 4); ) {
			page[i++] = 0;
			page[i++] = 0;
			page[i++] = 0;
			page[i++] = (unsigned char)rand();
		}
		return;

	/* return a page that looks kinda like a struct */
	case 6:	fabricate_onepage_struct(page);
		return;

	/* return a page of unicode nonsense. */
	case 7:	gen_unicode_page(page);
		return;

	/* page of 0's and 1's. */
	case 8:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand_bool();
		return;

	/* page full of format strings. */
	case 9:
		for (i = 0; i < page_size; ) {
			page[i++] = '%';
			switch (rand_bool()) {
			case 0:	page[i++] = 'd';
				break;
			case 1:	page[i++] = 's';
				break;
			}
		}
		page_size = getpagesize();	// Hack for clang 3.3 false positive.
		page[rand() % page_size] = 0;
		return;

	/* ascii representation of a random number */
	case 10:
		switch (rand() % 3) {
		case 0:
			switch (rand() % 3) {
			case 0:	p = sprintf(page_rand, "%lu", (unsigned long) rand64());
				break;
			case 1:	p = sprintf(page_rand, "%ld", (unsigned long) rand64());
				break;
			case 2:	p = sprintf(page_rand, "%lx", (unsigned long) rand64());
				break;
			}
			break;

		case 1:
			switch (rand() % 3) {
			case 0:	p = sprintf(page_rand, "%u", (unsigned int) rand64());
				break;
			case 1:	p = sprintf(page_rand, "%d", (int) rand64());
				break;
			case 2:	p = sprintf(page_rand, "%x", (int) rand64());
				break;
			}
			break;

		case 2:
			switch (rand() % 3) {
			case 0:	p = sprintf(page_rand, "%u", (unsigned char) rand64());
				break;
			case 1:	p = sprintf(page_rand, "%d", (char) rand64());
				break;
			case 2:	p = sprintf(page_rand, "%x", (char) rand64());
				break;
			}
			break;

		}

		page_rand[p] = 0;
		break;
	}
}

void init_page_rand(void)
{
	page_rand = (char *) memalign(page_size, page_size * 2);
	if (!page_rand)
		exit(EXIT_FAILURE);

	output(2, "page_rand @ %p\n", page_rand);

	generate_random_page(page_rand);
}
