#include <stdlib.h>

#include "trinity.h"	// page_size
#include "sanitise.h"

unsigned long get_len(void)
{
	int i = 0;

	i = get_interesting_value();

	if (i == 0)
		return 0;

	switch (rand() % 6) {

	case 0:	i &= 0xff;
		break;
	case 1: i &= page_size;
		break;
	case 2:	i &= 0xffff;
		break;
	case 3:	i &= 0xffffff;
		break;
	case 4:	i &= 0xffffffff;
		break;
	default:
		// Pass through
		break;
	}

	/* we might get lucky if something is counting ints/longs etc. */
	if (rand() % 100 < 25) {
		switch (rand() % 3) {
		case 0:	i /= sizeof(int);
			break;
		case 1:	i /= sizeof(long);
			break;
		case 2:	i /= sizeof(long long);
			break;
		default:
			break;
		}
	}

	return i;
}
