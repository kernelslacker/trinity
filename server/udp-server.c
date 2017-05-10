#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "udp.h"
#include "udp-server.h"

// TODO: ipv6

struct sockaddr_in udpclient;

int socketfd;

#define MAXBUF 10240
char buf[MAXBUF];

void sendudp(char *buffer, size_t len)
{
	int ret;

	ret = sendto(socketfd, buffer, len, 0, (struct sockaddr *) &udpclient, sizeof(udpclient));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

size_t readudp(void)
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

bool setup_socket(void)
{
	struct sockaddr_in udpserver;
	int rcvbuf;
	int ret;

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

	rcvbuf = 1000000 * 64;	//TODO: adjust 64 to max_children
	ret = setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (ret == 0)
		printf("Recieve socket buffer size set to %d\n", rcvbuf);

	return TRUE;
}
