#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
#include "compat.h"

void gen_nfc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_nfc *nfc;

	// TODO: See also sockaddr_nfc_llcp
	nfc = malloc(sizeof(struct sockaddr_nfc));
	if (nfc == NULL)
		return;

	nfc->sa_family = PF_NFC;
	nfc->dev_idx = rand();
	nfc->target_idx = rand();
	nfc->nfc_protocol = rand() % 5;
	*addr = (unsigned long) nfc;
	*addrlen = sizeof(struct sockaddr_nfc);
}
