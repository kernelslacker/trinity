#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/atm.h>
#include <stdlib.h>

void gen_atmpvc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = malloc(sizeof(struct sockaddr_atmpvc));
	if (atmpvc == NULL)
		return;

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rand();
	atmpvc->sap_addr.vpi = rand();
	atmpvc->sap_addr.vci = rand();
	*addr = (unsigned long) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}
