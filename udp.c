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

void sendudp(char *buffer)
{
	int ret;

	if (logging_enabled == FALSE)
		return;

	ret = sendto(logsocket, buffer, strlen(buffer), 0, (struct sockaddr *) &udpserver, sizeof(udpserver));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

static bool handshake(void)
{
	int ret;
	socklen_t addrlen = 0;
	char hello[] = "Trinity proto v" __stringify(TRINITY_UDP_VERSION);
	char expectedreply[] = "Trinity server v" __stringify(TRINITY_UDP_VERSION) ". Go ahead";
	char buf[MAXBUF];

	printf("Sending hello to logging server.\n");
	sendudp(hello);

	printf("Waiting for reply from logging server.\n");
	addrlen = sizeof(udpserver);
	ret = recvfrom(logsocket, buf, MAXBUF, 0, (struct sockaddr *) &udpserver, &addrlen);
	if (ret == -1) {
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
		return FALSE;
	}

	if (ret != (int) strlen(expectedreply)) {
		printf("Got wrong length expected reply: Should be %d but was %d : %s\n", (int) strlen(expectedreply), ret, buf);
		return FALSE;
	}
	if (strncmp(buf, expectedreply, strlen(expectedreply)) != 0) {
		printf("Got unregnized reply: (%d bytes) %s\n", ret, buf);
		printf("Expected %d bytes: %s\n", (int) strlen(expectedreply), expectedreply);
		return FALSE;
	}

	printf("Got reply from server. Logging enabled.\n");
	return TRUE;
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

	if (handshake() == FALSE)
		logging_enabled = FALSE;
}

void shutdown_logging(void)
{
	if (logging_enabled == FALSE)
		return;

	close(logsocket);
}
