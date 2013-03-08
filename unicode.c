/*
 * Routines for generating a page of mangled unicode.
 *
 * Inspiration:
 *  http://www.cl.cam.ac.uk/~mgk25/ucs/examples/quickbrown.txt
 *  http://www.columbia.edu/~fdc/utf8/
 *  http://www.cl.cam.ac.uk/~mgk25/unicode.html
 *  http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
 *  http://stackoverflow.com/questions/1319022/really-good-bad-utf-8-example-test-data
 *  http://www.twitter.com/glitchr
 *
 * Lots more to do here, but this is a start.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "trinity.h"

void gen_unicode_page(char *page)
{
	unsigned int i = 0, j, l;
	unsigned int unilen;

	char unicode1[4] = { 0xb8, 0xe0, 0xe0, 0xaa };
	char unicode2[6] = { 0x89, 0xb9, 0xb9, 0xe0, 0xe0, 0x89 };
	char unicode3[2] = { 0x89, 0xb9 };
	char unicode4[18] = { 0xbb, 0xef, 0xd2, 0xa9, 0xd2, 0x88, 0x20, 0x88, 0x88, 0xd2, 0x88, 0xd2, 0xd2, 0x20, 0xd2, 0x88, 0x0a, 0x88 };
	char unicode5[4] = { 0xd9, 0x20, 0xd2, 0x87 };
	char unicode6[4] = { 0xcc, 0x88, 0xd2, 0xbf };
	char unicode7[2] = { 0x0a, 0xbf };

	char *ptr = page;

	while (i < (page_size - 4)) {

		j = rand() % 7;

		switch (j) {

		case 0:
			strncpy(ptr, unicode1, 4);
			ptr += 4;
			i += 4;
			break;

		case 1: unilen = rand() % 10;
			for (l = 0; l < unilen; l++) {
				strncpy(ptr, unicode2, 6);
				ptr += 6;
				i += 6;
				if ((i + 6) > page_size)
					break;
			}
			break;

		case 2:	strncpy(ptr, unicode3, 2);
			i += 2;
			ptr += 2;
			break;
		case 3:	strncpy(ptr, unicode4, 18);
			i += 18;
			ptr += 18;
			break;

		case 4:	strncpy(ptr, unicode5, 4);
			i += 4;
			ptr += 4;
			break;

		case 5: unilen = rand() % 10;
			for (l = 0; l < unilen; l++) {
				strncpy(ptr, unicode6, 4);
				ptr += 4;
				i += 4;
				if ((i + 4) > page_size)
					break;
			}
			break;

		case 6:	strncpy(ptr, unicode7, 4);
			i += 4;
			ptr += 4;
			break;

		default:
			break;
		}
	}

	page[rand() % page_size] = 0;
}
