#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "log.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

char *page_rand;

void init_page_rand(void)
{
	page_rand = (char *) memalign(page_size, page_size * 2);
	if (!page_rand)
		exit(EXIT_FAILURE);

	output(2, "page_rand @ %p\n", page_rand);

	generate_random_page(page_rand);
}
