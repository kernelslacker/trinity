#pragma once

#define TRINITY_LOG_PORT 6665

#define TRINITY_UDP_VERSION 1

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITED,
};
