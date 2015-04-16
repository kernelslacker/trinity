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
	{ "PF_UNSPEC",       0 },
	{ "PF_LOCAL",        1 },
	{ "PF_UNIX",         PF_LOCAL },
	{ "PF_FILE",         PF_LOCAL },
	{ "PF_INET",         2 },
	{ "PF_AX25",         3 },
	{ "PF_IPX",          4 },
	{ "PF_APPLETALK",    5 },
	{ "PF_NETROM",       6 },
	{ "PF_BRIDGE",       7 },
	{ "PF_ATMPVC",       8 },
	{ "PF_X25",          9 },
	{ "PF_INET6",        10 },
	{ "PF_ROSE",         11 },
	{ "PF_DECnet",       12 },
	{ "PF_NETBEUI",      13 },
	{ "PF_SECURITY",     14 },
	{ "PF_KEY",          15 },
	{ "PF_NETLINK",      16 },
	{ "PF_ROUTE",        PF_NETLINK },
	{ "PF_PACKET",       17 },
	{ "PF_ASH",          18 },
	{ "PF_ECONET",       19 },
	{ "PF_ATMSVC",       20 },
	{ "PF_RDS",          21 },
	{ "PF_SNA",          22 },
	{ "PF_IRDA",         23 },
	{ "PF_PPPOX",        24 },
	{ "PF_WANPIPE",      25 },
	{ "PF_LLC",          26 },
	{ "PF_IB",           27 },
	{ "PF_MPLS",         28 },
	{ "PF_CAN",          29 },
	{ "PF_TIPC",         30 },
	{ "PF_BLUETOOTH",    31 },
	{ "PF_IUCV",         32 },
	{ "PF_RXRPC",        33 },
	{ "PF_ISDN",         34 },
	{ "PF_PHONET",       35 },
	{ "PF_IEEE802154",   36 },
	{ "PF_CAIF",         37 },
	{ "PF_ALG",          38 },
	{ "PF_NFC",          39 },
	{ "PF_VSOCK",        40 },
};

static const struct domain *lookup_domain(const char *name, unsigned int domain)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		if ((name && strcmp(name, domains[i].name) == 0) ||
		    (domain != -1u && domains[i].domain == domain))
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

	p = lookup_domain(domainarg, specific_domain ? : -1u);
	if (p) {
		specific_domain = p->domain;
		output(2, "Using domain %s (%u) for all sockets\n", p->name, p->domain);
		return;
	}

	outputerr("Domain unknown. Pass a numeric value [0-%d] or one of ", TRINITY_PF_MAX);
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
		p = lookup_domain(tok, (unsigned int)atoi(tok));
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
