#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "net.h"
#include "domains.h"
#include "params.h"
#include "utils.h"
#include "compat.h"

struct domain {
	const char *name;
	const unsigned int domain;
};

static const struct domain domains[] = {
	{ "UNSPEC",	PF_UNSPEC },
	{ "LOCAL",	PF_LOCAL },
	{ "UNIX",	PF_LOCAL },
	{ "FILE",	PF_LOCAL },
	{ "INET",	PF_INET },
	{ "AX25",	PF_AX25 },
	{ "IPX",	PF_IPX },
	{ "APPLETALK",	PF_APPLETALK },
	{ "NETROM",	PF_NETROM },
	{ "BRIDGE",	PF_BRIDGE },
	{ "ATMPVC",	PF_ATMPVC },
	{ "X25",	PF_X25 },
	{ "INET6",	PF_INET6 },
	{ "ROSE",	PF_ROSE },
	{ "DECnet",	PF_DECnet },
	{ "NETBEUI",	PF_NETBEUI },
	{ "SECURITY",	PF_SECURITY },
	{ "KEY",	PF_KEY },
	{ "NETLINK",	PF_NETLINK },
	{ "ROUTE",	PF_NETLINK },
	{ "PACKET",	PF_PACKET },
	{ "ASH",	PF_ASH },
	{ "ECONET",	PF_ECONET },
	{ "ATMSVC",	PF_ATMSVC },
	{ "RDS",	PF_RDS },
	{ "SNA",	PF_SNA },
	{ "IRDA",	PF_IRDA },
	{ "PPPOX",	PF_PPPOX },
	{ "WANPIPE",	PF_WANPIPE },
	{ "LLC",	PF_LLC },
	{ "IB",		PF_IB  },
	{ "MPLS",	PF_MPLS },
	{ "CAN",	PF_CAN },
	{ "TIPC",	PF_TIPC },
	{ "BLUETOOTH",	PF_BLUETOOTH },
	{ "IUCV",	PF_IUCV },
	{ "RXRPC",	PF_RXRPC },
	{ "ISDN",	PF_ISDN },
	{ "PHONET",	PF_PHONET },
	{ "IEEE802154",	PF_IEEE802154 },
	{ "CAIF",	PF_CAIF },
	{ "ALG",	PF_ALG },
	{ "NFC",	PF_NFC },
	{ "VSOCK",	PF_VSOCK },
	{ "KCM",	PF_KCM },
	{ "QIPCRTR",	PF_QIPCRTR },
	{ "SMC",	PF_SMC },
	{ "XDP",	PF_XDP },
};

static const struct domain *lookup_domain(const char *name)
{
	unsigned int i, len;

	if (!name)
		return NULL;

	len = strlen(name);

	if (strncmp(name, "PF_", 3) == 0) {
		name += 3;
		len-=3;
	}

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		if (len != strlen(domains[i].name))
			continue;
		if (strncmp(name, domains[i].name, len) == 0)
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
