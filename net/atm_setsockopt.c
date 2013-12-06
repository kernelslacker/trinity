#include <stdlib.h>
#include <linux/atmdev.h>
#include <linux/atm.h>
#include "maps.h"	// page_rand
#include "net.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

#define NR_SOL_ATM_OPTS ARRAY_SIZE(atm_opts)
static const unsigned int atm_opts[] = {
	SO_SETCLP, SO_CIRANGE, SO_ATMQOS, SO_ATMSAP, SO_ATMPVC, SO_MULTIPOINT };

void atm_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_ATM;

	val = rand() % NR_SOL_ATM_OPTS;
	so->optname = atm_opts[val];
}
