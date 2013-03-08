#include <stdio.h>
#include <stdlib.h>

#include "trinity.h"	// page_size
#include "sanitise.h"	// interesting_*
#include "log.h"	// For BUG

void fabricate_onepage_struct(char *page)
{
	void *addr;
	unsigned int i, j;

	for (i = 0; i < page_size; i++) {
		j = rand() % 4;
		switch (j) {
		case 0: page[i] = get_interesting_32bit_value();
			i += sizeof(unsigned long);
			break;
		case 1: page[i] = get_interesting_value();
			i += sizeof(unsigned long long);
			break;
		case 2: addr = get_address();
			page[i] = (unsigned long) addr;
			i += sizeof(unsigned long);
			break;
		case 3: page[i] = (unsigned int) rand() % page_size;
			i += sizeof(unsigned int);
			break;
		default:
			BUG("unreachable!\n");
			return;
		}
	}
}

void generate_random_page(char *page)
{
	unsigned int i;
	unsigned int type = rand() % 5;

	switch (type) {
	/* return a page of complete trash */
	case 0:	/* bytes */
		for (i = 0; i < page_size; i++)
			page[i++] = (unsigned char)rand();
		return;

	case 1:	/* ints */
		for (i = 0; i < (page_size / 2); i++) {
			page[i++] = 0;
			page[i++] = (unsigned char)rand();
		}
		return;

	case 2:	/* longs */
		for (i = 0; i < (page_size / 4); i++) {
			page[i++] = 0;
			page[i++] = 0;
			page[i++] = 0;
			page[i++] = (unsigned char)rand();
		}
		return;

	/* return a page that looks kinda like a struct */
	case 3:	fabricate_onepage_struct(page);
		return;

	/* return a page of unicode nonsense. */
	case 4:	gen_unicode_page(page);
		return;

	default:
		BUG("unreachable!\n");
		return;
	}
}
