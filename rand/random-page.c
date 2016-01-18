/*
 * Routines to dirty a range of memory.
 */

#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

void generate_rand_bytes(unsigned char *ptr, unsigned int len)
{
	unsigned int i;
	unsigned int startoffset = 0, remain;
	unsigned char separators[] = { ':', ',', '.', ' ', '-', '\0', };
	unsigned char separator;

	switch (rnd() % 3) {
	case 0:
		/* Complete garbage. */
		for (i = 0; i < len; i++)
			ptr[i] = RAND_BYTE();
		break;
	case 1:
		/* printable text strings. */
		for (i = 0; i < len; i++)
			ptr[i] = 32 + rnd() % (0x7f - 32);
		break;
	case 2:
		/* numbers (for now, decimal only) */

		separator = separators[rnd() % sizeof(separators)];

		remain = len;

		while (remain > 0) {
			unsigned int runlen;

			/* Sometimes make the numbers be negative. */
			if (RAND_BOOL()) {
				ptr[startoffset++] = '-';
				remain--;
				if (remain == 0)
					break;
			}

			/* At most make this run 10 chars. */
			runlen = min(remain, (unsigned int) rnd() % 10);

			for (i = startoffset; i < startoffset + runlen; i++)
				ptr[i] = '0' + rnd() % 10;

			startoffset += runlen;
			remain -= runlen;

			/* insert commas and/or spaces */
			if (remain > 0) {
				ptr[i++] = separator;
				startoffset++;
				remain--;
			}
		}
		break;
	}
}

static void fabricate_onepage_struct(char *page)
{
	unsigned int i;

	for (i = 0; i < page_size; ) {
		void **ptr;

		ptr = (void*) &page[i];

		/* 4 byte (32bit) 8 byte (64bit) alignment */
		if (i & ~((__WORDSIZE / 8) - 1)) {
			unsigned long val = 0;

			i += sizeof(unsigned long);
			if (i > page_size)
				return;

			switch (rnd() % 4) {
			case 0:	val = rand64();
				break;
			case 1:	val = (unsigned long) get_address();
				break;
			case 2:	val = (unsigned long) ptr;
				break;
			case 3:	val = get_len();
				break;
			}

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
	char *p;

	switch (rnd() % 8) {

	case 0:
		memset(page, 0, page_size);
		return;

	case 1:
		memset(page, 0xff, page_size);
		return;

	case 2:
		memset(page, RAND_BYTE(), page_size);
		return;

	case 3:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rnd();
		return;

	case 4:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)RAND_BOOL();
		return;

	/* return a page that looks kinda like a struct */
	case 5:	fabricate_onepage_struct(page);
		return;

	/* page full of format strings. */
	case 6:
		for (i = 0; i < page_size; i += 2) {
			page[i] = '%';
			switch (RAND_BOOL()) {
			case 0:	page[i + 1] = 'd';
				break;
			case 1:	page[i + 1] = 's';
				break;
			}
		}
		page_size = getpagesize();	// Hack for clang 3.3 false positive.
		page[rnd() % page_size] = 0;
		return;

	/* ascii representation of a random number */
	case 7:
		p = page;

		if (RAND_BOOL()) {
			/* hex */
			switch (rnd() % 3) {
			case 0:	p += sprintf(p, "0x%lx", (unsigned long) rand64());
				break;
			case 1:	p += sprintf(p, "0x%lx", (unsigned long) rand64());
				break;
			case 2:	p += sprintf(p, "0x%x", (int) rand32());
				break;
			}
		} else {
			/* decimal */

			/* perhaps negative ?*/
			if (RAND_BOOL())
				p += sprintf(p, "-");

			switch (rnd() % 3) {
			case 0:	p += sprintf(p, "%lu", (unsigned long) rand64());
				break;
			case 1:	p += sprintf(p, "%u", (unsigned int) rand32());
				break;
			case 2:	p += sprintf(p, "%u", (unsigned char) rnd());
				break;
			}
		}

		*p = 0;
		break;
	}
}
