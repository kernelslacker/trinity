#include "trinity.h"

void sanitise_sendto(__unused__ unsigned long *fd,
	__unused__ unsigned long *buff,
	__unused__ unsigned long *len,
	__unused__ unsigned long *flags,
	__unused__ unsigned long *addr,
	unsigned long *addr_len)
{
	*addr_len %= 128;	// MAX_SOCK_ADDR
}
