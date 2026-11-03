/*
 * Socket domain tables for the socket() sanitiser that
 * sanitiser_owned_mask_test.c runs: every family enabled, none with a
 * protocol table, so a draw falls back to a random type.  Nothing
 * disables a family, so the search for the next enabled one aborts.
 * Also the socket() seam every netlink socket of the test binary goes
 * through.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "domains.h"
#include "net.h"
#include "params.h"

bool no_domains[TRINITY_PF_MAX];
bool do_specific_domain;
unsigned int specific_domain;
const struct protoptr net_protocols[TRINITY_PF_MAX];

/*
 * What a netlink socket() returns.  A test that opens one sets this for
 * its call and clears it after; unset, AF_NETLINK fails, so nothing here
 * can reach a real netlink socket.  Every other domain goes to the real
 * call.
 */
int (*fake_netlink_socket)(int type, int protocol);

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
	if (domain != AF_NETLINK)
		return __real_socket(domain, type, protocol);
	if (fake_netlink_socket == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}
	return fake_netlink_socket(type, protocol);
}

unsigned int find_next_enabled_domain(unsigned int from)
{
	(void)from;
	fprintf(stderr, "fake find_next_enabled_domain called unexpectedly\n");
	abort();
}
