/*
 * Socket domain tables for the socket() sanitiser that
 * sanitiser_owned_mask_test.c runs: every family enabled, none with a
 * protocol table, so a draw falls back to a random type.  Nothing
 * disables a family, so the search for the next enabled one aborts.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "domains.h"
#include "net.h"
#include "params.h"

bool no_domains[TRINITY_PF_MAX];
bool do_specific_domain;
unsigned int specific_domain;
const struct protoptr net_protocols[TRINITY_PF_MAX];

unsigned int find_next_enabled_domain(unsigned int from)
{
	(void)from;
	fprintf(stderr, "fake find_next_enabled_domain called unexpectedly\n");
	abort();
}
