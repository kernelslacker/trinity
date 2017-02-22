#pragma once

#define TRINITY_LOG_PORT 6665

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer);
