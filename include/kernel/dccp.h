#pragma once

#include <linux/dccp.h>

#ifndef DCCP_SOCKOPT_PACKET_SIZE
#define DCCP_SOCKOPT_PACKET_SIZE        1
#define DCCP_SOCKOPT_SERVICE_CODE       2
#define DCCP_SOCKOPT_CHANGE_L           3
#define DCCP_SOCKOPT_CHANGE_R           4
#define DCCP_SOCKOPT_GET_CUR_MPS        5
#define DCCP_SOCKOPT_SERVER_TIMEWAIT    6
#define DCCP_SOCKOPT_SEND_CSCOV         10
#define DCCP_SOCKOPT_RECV_CSCOV         11
#define DCCP_SOCKOPT_AVAILABLE_CCIDS    12
#define DCCP_SOCKOPT_CCID               13
#define DCCP_SOCKOPT_TX_CCID            14
#define DCCP_SOCKOPT_RX_CCID            15
#define DCCP_SOCKOPT_QPOLICY_ID         16
#define DCCP_SOCKOPT_QPOLICY_TXQLEN     17
#define DCCP_SOCKOPT_CCID_RX_INFO       128
#define DCCP_SOCKOPT_CCID_TX_INFO       192
#define DCCP_SOCKOPT_GET_CUR_MPS        5
#endif
