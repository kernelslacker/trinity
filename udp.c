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

static int logging_enabled = FALSE;

static int logsocket = -1;

static struct sockaddr_in udpserver;

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

	logging_enabled = TRUE;
}

void sendudp(char *buffer)
{
	int ret;

	if (logging_enabled == FALSE)
		return;

	ret = sendto(logsocket, buffer, strlen(buffer) + 1, 0, (struct sockaddr *) &udpserver, sizeof(udpserver));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

void shutdown_logging(void)
{
	if (logging_enabled == FALSE)
		return;

	close(logsocket);
}
