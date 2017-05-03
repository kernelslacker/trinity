#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "decode.h"
#include "exit.h"
#include "handshake.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

// TODO: ipv6

struct sockaddr_in udpclient;

int socketfd;

#define MAXBUF 10240
static char buf[MAXBUF];

void sendudp(char *buffer, size_t len)
{
	int ret;

	ret = sendto(socketfd, buffer, len, 0, (struct sockaddr *) &udpclient, sizeof(udpclient));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

static size_t readudp(void)
{
	int ret;
	socklen_t addrlen = 0;

	memset(buf, 0, MAXBUF);

	addrlen = sizeof(udpclient);
	ret = recvfrom(socketfd, buf, MAXBUF, 0, (struct sockaddr *) &udpclient, &addrlen);
	if (ret == -1)
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));

	return ret;
}

/* simple 2-way handshake just to agree on protocol. */
static bool __handshake(void)
{
	struct hellostruct *hs = (struct hellostruct *) buf;

	/* if we got here, we know we got a correct size message, but the contents
	 * need to match also for it to be a handshake.
	 */
	if (strncmp((char *)hs->hello, "Trinity\0", HELLOLEN) != 0)
		return FALSE;

	printf("Handshake request. (Pid:%d Numchildren:%d) sending reply (%ld bytes)\n",
			hs->mainpid, hs->num_children, strlen(serverreply));

	sendudp(serverreply, strlen(serverreply));
	return TRUE;
}

static void handshake(void)
{
	int ret = -1;

retry:	while (ret != sizeof(struct hellostruct))
		ret = readudp();

	if (__handshake() == FALSE) {
		ret = -1;
		goto retry;
	}
}

static bool check_handshake(int ret)
{
	if (ret != sizeof(struct hellostruct))
		return FALSE;

	return __handshake();
}

static bool setup_socket(void)
{
	struct sockaddr_in udpserver;

	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd == -1) {
		fprintf(stderr, "Could not create a socket\n");
		return FALSE;
	}

	udpserver.sin_family = AF_INET;
	udpserver.sin_addr.s_addr = htonl(INADDR_ANY);
	udpserver.sin_port = htons(TRINITY_LOG_PORT);

	if (bind(socketfd, (struct sockaddr *) &udpserver, sizeof(udpserver)) != 0) {
		fprintf(stderr, "Could not bind to address!\n");
		close(socketfd);
		return FALSE;
	}
	return TRUE;
}

int main(__unused__ int argc, __unused__ char* argv[])
{
	int ret;

	if (setup_socket() == FALSE)
		goto out;

	handshake();

	while (1) {
		enum logmsgtypes type;

		ret = readudp();

		// If something went wrong, just ignore and try again.
		if (ret <= 0)
			continue;

		/* We may see a new handshake appear at any time
		 * if a client dies without sending a 'main has exited' message.
		 * Just re-handshake for now. Later, we'll tear down any context etc.
		 */
		if (check_handshake(ret) == TRUE)
			continue;

		type = buf[0];

		if (type >= MAX_LOGMSGTYPE) {
			int i;

			printf("Unknown msgtype: %d\n", type);

			/* Unknown command (yet). Just dump as hex. */
			printf("rx %d bytes: ", ret);
			for (i = 0; i < ret; i++) {
				printf("%x ", (unsigned char) buf[i]);
			}
			printf("\n");
			continue;
		}

		decodefuncs[type].func((char *)&buf);
	}

	close(socketfd);
out:
	exit(EXIT_FAILURE);
}
