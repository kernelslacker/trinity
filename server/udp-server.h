#pragma once

extern struct sockaddr_in udpclient;

extern int socketfd;

#define MAXBUF 10240
extern char buf[MAXBUF];

void sendudp(char *buffer, size_t len);
size_t readudp(void);
bool setup_socket(void);
