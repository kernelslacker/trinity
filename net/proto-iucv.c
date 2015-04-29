#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

static const unsigned int iucv_opts[] = {
	SO_IPRMDATA_MSG, SO_MSGLIMIT, SO_MSGSIZE
};

void iucv_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % ARRAY_SIZE(iucv_opts);
	so->optname = iucv_opts[val];

	so->optlen = sizeof(int);
}
