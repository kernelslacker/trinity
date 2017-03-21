#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "trinity.h"
#include "udp.h"
#include "utils.h"

#define MAXBUF 1024

static int logging_enabled = FALSE;

static int logsocket = -1;

static struct sockaddr_in udpserver;

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
	int ret;
	socklen_t addrlen = sizeof(udpserver);
	fd_set rfds;
	struct timeval tv;
	char hello[] = "Trinity proto v" __stringify(TRINITY_UDP_VERSION);
	char expectedreply[] = "Trinity server v" __stringify(TRINITY_UDP_VERSION) ". Go ahead";
	char buf[MAXBUF];

	printf("Sending hello to logging server.\n");
	sendudp(hello, strlen(hello));

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

		if (ret != (int) strlen(expectedreply)) {
			printf("Got wrong length expected reply: Should be %d but was %d : %s\n", (int) strlen(expectedreply), ret, buf);
			return FALSE;
		}
		if (strncmp(buf, expectedreply, strlen(expectedreply)) != 0) {
			printf("Got unrecognized reply: (%d bytes) %s\n", ret, buf);
			printf("Expected %d bytes: %s\n", (int) strlen(expectedreply), expectedreply);
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

void init_logging(char *optarg)
{
	struct hostent *he;
	struct sockaddr_in udpclient;
	struct in_addr **addr_list;
	char *ip;
	int ret;
	unsigned int i;

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

void shutdown_logging(void)
{
	if (logging_enabled == FALSE)
		return;

	close(logsocket);
}
