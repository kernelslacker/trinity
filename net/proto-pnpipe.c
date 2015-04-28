#include <stdlib.h>
#include "net.h"

void pnpipe_setsockopt(struct sockopt *so)
{
	so->level = SOL_PNPIPE;
}
