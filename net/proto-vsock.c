#include <sys/time.h>
#include <stdlib.h>
/* for struct sockaddr and sa_family_t, needed in vm_sockets.h, fixed by 22bbc1dcd0d6 */
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef SOL_VSOCK
#define SOL_VSOCK 287
#endif

#ifndef SO_VM_SOCKETS_BUFFER_SIZE
#define SO_VM_SOCKETS_BUFFER_SIZE	0
#endif
#ifndef SO_VM_SOCKETS_BUFFER_MIN_SIZE
#define SO_VM_SOCKETS_BUFFER_MIN_SIZE	1
#endif
#ifndef SO_VM_SOCKETS_BUFFER_MAX_SIZE
#define SO_VM_SOCKETS_BUFFER_MAX_SIZE	2
#endif
#ifndef SO_VM_SOCKETS_PEER_HOST_VM_ID
#define SO_VM_SOCKETS_PEER_HOST_VM_ID	3
#endif
#ifndef SO_VM_SOCKETS_TRUSTED
#define SO_VM_SOCKETS_TRUSTED		5
#endif
#ifndef SO_VM_SOCKETS_CONNECT_TIMEOUT
#define SO_VM_SOCKETS_CONNECT_TIMEOUT	6
#endif
#ifndef SO_VM_SOCKETS_NONBLOCK_TXRX
#define SO_VM_SOCKETS_NONBLOCK_TXRX	7
#endif

static void vsock_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_vm *vm;
	static const unsigned int cids[] = {
		VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR,
		VMADDR_CID_LOCAL, VMADDR_CID_HOST,
	};

	vm = zmalloc(sizeof(struct sockaddr_vm));
	vm->svm_family = AF_VSOCK;
	vm->svm_reserved1 = 0;

	if (RAND_BOOL())
		vm->svm_cid = RAND_ARRAY(cids);
	else
		vm->svm_cid = rand();

	if (RAND_BOOL())
		vm->svm_port = VMADDR_PORT_ANY;
	else
		vm->svm_port = rand();

	vm->svm_flags = RAND_BOOL() ? VMADDR_FLAG_TO_HOST : 0;

	*addr = (struct sockaddr *) vm;
	*addrlen = sizeof(struct sockaddr_vm);
}

static const unsigned int vsock_opts[] = {
	SO_VM_SOCKETS_BUFFER_SIZE,
	SO_VM_SOCKETS_BUFFER_MIN_SIZE,
	SO_VM_SOCKETS_BUFFER_MAX_SIZE,
	SO_VM_SOCKETS_PEER_HOST_VM_ID,
	SO_VM_SOCKETS_TRUSTED,
	SO_VM_SOCKETS_CONNECT_TIMEOUT,
	SO_VM_SOCKETS_NONBLOCK_TXRX,
};

static void vsock_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned long long *optval64;
	unsigned int *optval32;
	struct timeval *tv;

	so->level = SOL_VSOCK;
	so->optname = RAND_ARRAY(vsock_opts);

	switch (so->optname) {
	case SO_VM_SOCKETS_BUFFER_SIZE:
	case SO_VM_SOCKETS_BUFFER_MIN_SIZE:
	case SO_VM_SOCKETS_BUFFER_MAX_SIZE:
		optval64 = (unsigned long long *) so->optval;
		*optval64 = rand64();
		so->optlen = sizeof(unsigned long long);
		break;
	case SO_VM_SOCKETS_CONNECT_TIMEOUT:
		tv = (struct timeval *) so->optval;
		tv->tv_sec = rand() % 60;
		tv->tv_usec = rand() % 1000000;
		so->optlen = sizeof(struct timeval);
		break;
	default:
		optval32 = (unsigned int *) so->optval;
		*optval32 = rand();
		so->optlen = sizeof(unsigned int);
		break;
	}
}

static struct socket_triplet vsock_triplets[] = {
	{ .family = PF_VSOCK, .protocol = 0, .type = SOCK_STREAM },
	{ .family = PF_VSOCK, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_VSOCK, .protocol = 0, .type = SOCK_SEQPACKET },
};

const struct netproto proto_vsock = {
	.name = "vsock",
	.gen_sockaddr = vsock_gen_sockaddr,
	.setsockopt = vsock_setsockopt,
	.valid_triplets = vsock_triplets,
	.nr_triplets = ARRAY_SIZE(vsock_triplets),
};
