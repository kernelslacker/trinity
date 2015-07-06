#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int iucv_opts[] = {
	SO_IPRMDATA_MSG, SO_MSGLIMIT, SO_MSGSIZE
};

void iucv_setsockopt(struct sockopt *so)
{
	so->optname = RAND_ARRAY(iucv_opts);

	so->optlen = sizeof(int);
}
