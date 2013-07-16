#include "net.h"

void rds_rand_socket(struct proto_type *pt)
{
	pt->protocol = 0;
	pt->type = SOCK_SEQPACKET;
}
