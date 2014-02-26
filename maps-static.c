#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "log.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

/* "static" pages. */
char *page_zeros;
char *page_0xff;
char *page_rand;
unsigned long *page_allocs;
unsigned long *page_maps;

static void * __allocbuf(const char *name)
{
	void *ptr;

	ptr = memalign(page_size, page_size * 2);
	if (!ptr)
		exit(EXIT_FAILURE);
	output(2, "%s @ %p\n", name, ptr);
	return ptr;
}

void init_shared_pages(void)
{
	unsigned int i;

	// a page of zeros
	page_zeros = __allocbuf("page_zeros");
	memset(page_zeros, 0, page_size * 2);

	// a page of 0xff
	page_0xff = __allocbuf("page_0xff");
	memset(page_0xff, 0xff, page_size * 2);

	// a page of random crap (overwritten below)
	page_rand = __allocbuf("page_rand");

	// page containing ptrs to mallocs.
	page_allocs = __allocbuf("page_allocs");
	for (i = 0; i < (page_size / sizeof(unsigned long *)); i++)
		page_allocs[i] = (unsigned long) malloc(page_size);

	// a page of ptrs to mmaps (set up at child init time).
	page_maps = __allocbuf("page_maps");

	// mmaps that get shared across children.
	setup_shared_mappings();

	// generate_random_page may end up using shared_mappings, so has to be last.
	generate_random_page(page_rand);
}
