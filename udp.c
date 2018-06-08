#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "child.h"
#include "handshake.h"
#include "trinity.h"
#include "udp.h"
#include "utils.h"

#define MAXBUF 1024

int logging_enabled = FALSE;

static int logsocket = -1;

static struct sockaddr_in udpserver;

void init_msghdr(struct trinity_msghdr *hdr, enum logmsgtypes type)
{
	hdr->type = type;
	hdr->pid = getpid();
}

void init_msgchildhdr(struct trinity_msgchildhdr *hdr, enum logmsgtypes type, pid_t pid, int childno)
{
	clock_gettime(CLOCK_MONOTONIC, &hdr->tp);

	hdr->type = type;
	hdr->pid = pid;
	hdr->childno = childno;
}

void init_msgobjhdr(struct trinity_msgobjhdr *hdr, enum logmsgtypes type, bool global, struct object *obj)
{
	hdr->type = type;
	hdr->pid = getpid();
	hdr->global = global;
	hdr->address = obj;
}

void sendudp(char *buffer, size_t len)
{
	int ret;

	if (logging_enabled == FALSE)
		return;

	ret = sendto(logsocket, buffer, len, 0, (struct sockaddr *) &udpserver, sizeof(udpserver));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

static bool __handshake(void)
{
	struct hellostruct hello;
	int ret;
	socklen_t addrlen = sizeof(udpserver);
	fd_set rfds;
	struct timeval tv;
	char buf[MAXBUF];

	snprintf(hello.hello, HELLOLEN, "Trinity");
	hello.version = TRINITY_UDP_VERSION;
	hello.mainpid = getpid();
	hello.num_children = max_children;

	printf("Sending hello to logging server.\n");
	sendudp((char *) &hello, sizeof(struct hellostruct));

	printf("Waiting for reply from logging server.\n");

	FD_ZERO(&rfds);

	/* Wait up to five seconds. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	FD_SET(logsocket, &rfds);

	ret = select(logsocket + 1, &rfds, NULL, NULL, &tv);
	if (ret == -1)
		perror("select()");
	else if (ret) {
		if (FD_ISSET(logsocket, &rfds) != TRUE) {
			printf("Something happened, but not on logsocket\n");
			return FALSE;
		}
		ret = recvfrom(logsocket, buf, MAXBUF, 0, (struct sockaddr *) &udpserver, &addrlen);
		if (ret == -1) {
			printf("recvfrom: %s\n", strerror(errno));
			return FALSE;
		}

		if (ret != (int) strlen(serverreply)) {
			printf("Got wrong length expected reply: Should be %d but was %d : %s\n", (int) strlen(serverreply), ret, buf);
			return FALSE;
		}
		if (strncmp(buf, serverreply, strlen(serverreply)) != 0) {
			printf("Got unrecognized reply: (%d bytes) %s\n", ret, buf);
			printf("Expected %d bytes: %s\n", (int) strlen(serverreply), serverreply);
			return FALSE;
		}
		/* handshake complete. */
		return TRUE;
	}
	return FALSE;
}

static bool handshake(void)
{
	int try;

	for (try = 1; try < 4; try++) {
		int ret = __handshake();
		if (ret == TRUE) {
			printf("Got reply from server. Logging enabled.\n");
			return TRUE;
		}
		printf("No reply within five seconds, resending hello. [%d/3].\n", try);
	}

	printf("Logging server seems down. Logging disabled.\n");
	return FALSE;
}

void init_udp_logging(char *optarg)
{
	struct hostent *he;
	struct sockaddr_in udpclient;
	struct in_addr **addr_list;
	char *ip = NULL;
	int ret;
	unsigned int i;
	int sendbuff;

	if (optarg == NULL) {
		logging_enabled = FALSE;
		return;
	}

	if ((he = gethostbyname(optarg)) == NULL) {
		printf("gethostbyname:%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	addr_list = (struct in_addr **)he->h_addr_list;
	for (i = 0; addr_list[i] != NULL; i++) {
		ip = inet_ntoa(*addr_list[i]);

		udpserver.sin_family = AF_INET;
		udpserver.sin_addr.s_addr = inet_addr(ip);
		udpserver.sin_port = htons(TRINITY_LOG_PORT);
	}

	if (ip == NULL)
		return;

	printf("Logging to %s\n", ip);

	logsocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (logsocket == -1) {
		printf("Could not create a socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	udpclient.sin_family = AF_INET;
	udpclient.sin_addr.s_addr = INADDR_ANY;
	udpclient.sin_port = 0;

	ret = bind(logsocket, (struct sockaddr *) &udpclient, sizeof(udpclient));
	if (ret != 0) {
		printf("Could not bind to address: %s\n", strerror(errno));
		close(logsocket);
		exit(EXIT_FAILURE);
	}

	sendbuff = 1000000 * max_children;
	ret = setsockopt(logsocket, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
	printf("socket buffer size set to: %d. (res:%s)\n", sendbuff, strerror(errno));

	/* We temporarily turn enabled on, as we need it for sendudp to work.
	 * If we don't get a valid handshake we turn it back off.
	 */
	logging_enabled = TRUE;

	if (handshake() == FALSE) {
		logging_enabled = FALSE;
		close(logsocket);
		logsocket = -1;
	}
}

void shutdown_udp_logging(void)
{
	if (logging_enabled == FALSE)
		return;

	close(logsocket);
}
