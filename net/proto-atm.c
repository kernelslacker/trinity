#include <stdlib.h>
#include <linux/atmdev.h>
#include <linux/atm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "net.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

void atmpvc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = zmalloc(sizeof(struct sockaddr_atmpvc));

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rand();
	atmpvc->sap_addr.vpi = rand();
	atmpvc->sap_addr.vci = rand();
	*addr = (struct sockaddr *) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}

void atmsvc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmsvc *atmsvc;
	unsigned int i;

	atmsvc = zmalloc(sizeof(struct sockaddr_atmsvc));

	atmsvc->sas_family = PF_ATMSVC;
	for (i = 0; i < ATM_ESA_LEN; i++)
		atmsvc->sas_addr.prv[i] = rand();
	for (i = 0; i < ATM_E164_LEN; i++)
		atmsvc->sas_addr.pub[i] = rand();
	atmsvc->sas_addr.lij_type = rand();
	atmsvc->sas_addr.lij_id = rand();
	*addr = (struct sockaddr *) atmsvc;
	*addrlen = sizeof(struct sockaddr_atmsvc);
}

// TODO: If anyone gives a crap about ATM, we could do better
// here and separate the pvc and svc ops.
// Personally, I couldn't care less, so throw everything in the same array
// just to make this simpler.
static const unsigned int atm_opts[] = {
	SO_SETCLP, SO_CIRANGE, SO_ATMQOS, SO_ATMSAP, SO_ATMPVC, SO_MULTIPOINT,
};

void atm_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_ATM;

	val = rand() % ARRAY_SIZE(atm_opts);
	so->optname = atm_opts[val];
}
