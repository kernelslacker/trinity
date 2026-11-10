#pragma once

/*
 * The RDMA_NLDEV_CMD_* ops and RDMA_NLDEV_ATTR_* attributes are enum members
 * upstream, so #ifndef cannot tell whether <rdma/rdma_netlink.h> has one.
 * configure compile-tests the ones added since v6.12 and emits
 * HAVE_<SYMBOL>; the fallback below exists only where the header lacks the
 * member.
 */
#include <rdma/rdma_netlink.h>

#ifndef HAVE_RDMA_NLDEV_CMD_FRMR_POOLS_GET
#define RDMA_NLDEV_CMD_FRMR_POOLS_GET			29
#endif
#ifndef HAVE_RDMA_NLDEV_CMD_FRMR_POOLS_SET
#define RDMA_NLDEV_CMD_FRMR_POOLS_SET			30
#endif

#ifndef HAVE_RDMA_NLDEV_ATTR_STAT_OPCOUNTER_ENABLED
#define RDMA_NLDEV_ATTR_STAT_OPCOUNTER_ENABLED		104
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_KEY
#define RDMA_NLDEV_ATTR_FRMR_POOL_KEY			107
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ATS
#define RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ATS		108
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ACCESS_FLAGS
#define RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ACCESS_FLAGS	109
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_KEY_VENDOR_KEY
#define RDMA_NLDEV_ATTR_FRMR_POOL_KEY_VENDOR_KEY	110
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_KEY_NUM_DMA_BLOCKS
#define RDMA_NLDEV_ATTR_FRMR_POOL_KEY_NUM_DMA_BLOCKS	111
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOLS_AGING_PERIOD
#define RDMA_NLDEV_ATTR_FRMR_POOLS_AGING_PERIOD		115
#endif
#ifndef HAVE_RDMA_NLDEV_ATTR_FRMR_POOL_PINNED_HANDLES
#define RDMA_NLDEV_ATTR_FRMR_POOL_PINNED_HANDLES	116
#endif

/* The most a client name takes, from the kernel-internal
 * <rdma/rdma_netlink.h>: nldev_policy bounds RDMA_NLDEV_ATTR_CHARDEV_TYPE
 * with it. */
#ifndef RDMA_NLDEV_ATTR_CHARDEV_TYPE_SIZE
#define RDMA_NLDEV_ATTR_CHARDEV_TYPE_SIZE		32
#endif
