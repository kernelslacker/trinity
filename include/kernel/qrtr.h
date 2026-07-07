#pragma once

#if __has_include(<linux/qrtr.h>)
#include <linux/qrtr.h>
#else
#include <linux/socket.h>
struct sockaddr_qrtr {
    __kernel_sa_family_t sq_family;
    __u32 sq_node;
    __u32 sq_port;
};
#endif
#ifndef QRTR_NODE_BCAST
#define QRTR_NODE_BCAST		0xffffffffu
#endif
#ifndef QRTR_PORT_CTRL
#define QRTR_PORT_CTRL		0xfffffffeu
#endif
