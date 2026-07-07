#pragma once

#if __has_include(<netinet/sctp.h>)
#include <netinet/sctp.h>
#endif

#ifndef SCTP_RTOINFO
#define SCTP_RTOINFO    0
#define SCTP_ASSOCINFO  1
#define SCTP_INITMSG    2
#define SCTP_NODELAY    3               /* Get/set nodelay option. */
#define SCTP_AUTOCLOSE  4
#define SCTP_SET_PEER_PRIMARY_ADDR 5
#define SCTP_PRIMARY_ADDR       6
#define SCTP_ADAPTATION_LAYER   7
#define SCTP_DISABLE_FRAGMENTS  8
#define SCTP_PEER_ADDR_PARAMS   9
#define SCTP_DEFAULT_SEND_PARAM 10
#define SCTP_EVENTS     11
#define SCTP_I_WANT_MAPPED_V4_ADDR 12   /* Turn on/off mapped v4 addresses  */
#define SCTP_MAXSEG     13              /* Get/set maximum fragment. */
#define SCTP_STATUS     14
#define SCTP_GET_PEER_ADDR_INFO 15
#define SCTP_DELAYED_ACK_TIME   16
#define SCTP_CONTEXT    17
#define SCTP_FRAGMENT_INTERLEAVE        18
#define SCTP_PARTIAL_DELIVERY_POINT     19 /* Set/Get partial delivery point */
#define SCTP_MAX_BURST  20              /* Set/Get max burst */
#define SCTP_AUTH_CHUNK 21      /* Set only: add a chunk type to authenticate */
#define SCTP_HMAC_IDENT 22
#define SCTP_AUTH_KEY   23
#define SCTP_AUTH_ACTIVE_KEY    24
#define SCTP_AUTH_DELETE_KEY    25
#define SCTP_PEER_AUTH_CHUNKS   26      /* Read only */
#define SCTP_LOCAL_AUTH_CHUNKS  27      /* Read only */
#define SCTP_GET_ASSOC_NUMBER   28      /* Read only */
#define SCTP_GET_ASSOC_ID_LIST  29      /* Read only */
#define SCTP_AUTO_ASCONF       30
#define SCTP_PEER_ADDR_THLDS    31
#ifndef SCTP_RECVRCVINFO
#define SCTP_RECVRCVINFO	32
#define SCTP_RECVNXTINFO	33
#define SCTP_DEFAULT_SNDINFO	34
#define SCTP_AUTH_DEACTIVATE_KEY	35
#define SCTP_REUSE_PORT		36
#define SCTP_PEER_ADDR_THLDS_V2	37
#endif
#endif

#ifndef SCTP_SOCKOPT_BINDX_ADD
#define SCTP_SOCKOPT_BINDX_ADD  100     /* BINDX requests for adding addrs */
#define SCTP_SOCKOPT_BINDX_REM  101     /* BINDX requests for removing addrs. */
#define SCTP_SOCKOPT_PEELOFF    102     /* peel off association. */
#define SCTP_SOCKOPT_CONNECTX_OLD       107     /* CONNECTX old requests. */
#define SCTP_GET_PEER_ADDRS     108             /* Get all peer address. */
#define SCTP_GET_LOCAL_ADDRS    109             /* Get all local address. */
#define SCTP_SOCKOPT_CONNECTX   110             /* CONNECTX requests. */
#define SCTP_SOCKOPT_CONNECTX3  111     /* CONNECTX requests (updated) */
#define SCTP_GET_ASSOC_STATS    112	/* Read only */
#ifndef SCTP_PR_SUPPORTED
#define SCTP_PR_SUPPORTED		113
#define SCTP_DEFAULT_PRINFO		114
#define SCTP_PR_ASSOC_STATUS		115
#define SCTP_PR_STREAM_STATUS		116
#define SCTP_RECONFIG_SUPPORTED		117
#define SCTP_ENABLE_STREAM_RESET	118
#define SCTP_RESET_STREAMS		119
#define SCTP_RESET_ASSOC		120
#define SCTP_ADD_STREAMS		121
#define SCTP_SOCKOPT_PEELOFF_FLAGS	122
#define SCTP_STREAM_SCHEDULER		123
#define SCTP_STREAM_SCHEDULER_VALUE	124
#define SCTP_INTERLEAVING_SUPPORTED	125
#define SCTP_SENDMSG_CONNECT		126
#define SCTP_EVENT			127
#define SCTP_ASCONF_SUPPORTED		128
#define SCTP_AUTH_SUPPORTED		129
#define SCTP_ECN_SUPPORTED		130
#define SCTP_EXPOSE_POTENTIALLY_FAILED_STATE	131
#define SCTP_REMOTE_UDP_ENCAPS_PORT	132
#define SCTP_PLPMTUD_PROBE_INTERVAL	133
#endif
#endif

