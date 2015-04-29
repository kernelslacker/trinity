#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "log.h"
#include "net.h"
#include "domains.h"
#include "params.h"
#include "utils.h"

struct domain {
	const char *name;
	const unsigned int domain;
};

static const struct domain domains[] = {
	{ "UNSPEC",       0 },
	{ "LOCAL",        1 },
	{ "UNIX",         PF_LOCAL },
	{ "FILE",         PF_LOCAL },
	{ "INET",         2 },
	{ "AX25",         3 },
	{ "IPX",          4 },
	{ "APPLETALK",    5 },
	{ "NETROM",       6 },
	{ "BRIDGE",       7 },
	{ "ATMPVC",       8 },
	{ "X25",          9 },
	{ "INET6",        10 },
	{ "ROSE",         11 },
	{ "DECnet",       12 },
	{ "NETBEUI",      13 },
	{ "SECURITY",     14 },
	{ "KEY",          15 },
	{ "NETLINK",      16 },
	{ "ROUTE",        PF_NETLINK },
	{ "PACKET",       17 },
	{ "ASH",          18 },
	{ "ECONET",       19 },
	{ "ATMSVC",       20 },
	{ "RDS",          21 },
	{ "SNA",          22 },
	{ "IRDA",         23 },
	{ "PPPOX",        24 },
	{ "WANPIPE",      25 },
	{ "LLC",          26 },
	{ "IB",           27 },
	{ "MPLS",         28 },
	{ "CAN",          29 },
	{ "TIPC",         30 },
	{ "BLUETOOTH",    31 },
	{ "IUCV",         32 },
	{ "RXRPC",        33 },
	{ "ISDN",         34 },
	{ "PHONET",       35 },
	{ "IEEE802154",   36 },
	{ "CAIF",         37 },
	{ "ALG",          38 },
	{ "NFC",          39 },
	{ "VSOCK",        40 },
};

static const struct domain *lookup_domain(const char *name)
{
	unsigned int i;

	if (!name)
		return NULL;

	if (strncmp(name, "PF_", 3) == 0)
		name += 3;

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		if (strncmp(name, domains[i].name, strlen(domains[i].name)) == 0)
			return &domains[i];
	}

	return NULL;
}

const char * get_domain_name(unsigned int domain)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(domains); i++)
		if (domains[i].domain == domain)
			return domains[i].name;
	return NULL;
}

void find_specific_domain(const char *domainarg)
{
	const struct domain *p;
	unsigned int i;

	p = lookup_domain(domainarg);
	if (p) {
		specific_domain = p->domain;
		output(2, "Using domain %s for all sockets\n", p->name);
		return;
	}

	outputerr("Domain unknown. Pass one of ");
	for (i = 0; i < ARRAY_SIZE(domains); i++)
		outputerr("%s ", domains[i].name);
	outputerr("\n");

	exit(EXIT_FAILURE);
}

unsigned int find_next_enabled_domain(unsigned int from)
{
	unsigned int i;

	from %= ARRAY_SIZE(no_domains);

	for (i = from; i < ARRAY_SIZE(no_domains); i++) {
		if (no_domains[i] == FALSE)
			return no_domains[i];
	}

	for (i = 0; i < from; i++) {
		if (no_domains[i] == FALSE)
			return no_domains[i];
	}

	return -1u;
}

void parse_exclude_domains(const char *arg)
{
	char *_arg = strdup(arg);
	const struct domain *p;
	char *tok;

	if (!_arg) {
		outputerr("No free memory\n");
		exit(EXIT_FAILURE);
	}

	for (tok = strtok(_arg, ","); tok; tok = strtok(NULL, ",")) {
		p = lookup_domain(tok);
		if (p) {
			BUG_ON(p->domain >= ARRAY_SIZE(no_domains));
			no_domains[p->domain] = TRUE;
		} else
			goto err;
	}

	free(_arg);
	return;

err:
	free(_arg);
	outputerr("Domain unknown in argument %s\n", arg);
	exit(EXIT_FAILURE);
}
