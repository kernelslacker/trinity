#pragma once

#include <linux/rds.h>

#ifndef SO_RDS_TRANSPORT
#define SO_RDS_TRANSPORT	8
#endif
#ifndef SOL_RDS
#define SOL_RDS			276
#endif

#ifndef RDS_CANCEL_SENT_TO
#define RDS_CANCEL_SENT_TO              1
#define RDS_GET_MR                      2
#define RDS_FREE_MR                     3
#define RDS_RECVERR                     5
#define RDS_CONG_MONITOR                6
#define RDS_GET_MR_FOR_DEST             7
#endif

