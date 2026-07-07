#pragma once

/*
 * Wrapper around <linux/netfilter/nf_tables.h> that ships #ifndef-guarded
 * fallbacks for NFT_MSG_* / NFTA_* symbols added after our installed uapi
 * header.  Included only by its real consumers -- never pulled into
 * kernel headers, so editing them doesn't trigger a near-full-tree rebuild.
 */
#include <linux/netfilter/nf_tables.h>

#ifndef NFT_MSG_NEWTABLE
#define NFT_MSG_NEWTABLE		0
#define NFT_MSG_DELTABLE		2
#define NFT_MSG_NEWCHAIN		3
#define NFT_MSG_DELCHAIN		5
#define NFT_MSG_NEWRULE			6
#define NFT_MSG_DELRULE			8
#endif
#ifndef NFT_MSG_NEWFLOWTABLE
#define NFT_MSG_NEWFLOWTABLE		22
#define NFT_MSG_DELFLOWTABLE		24
#endif

#ifndef NFTA_TABLE_NAME
#define NFTA_TABLE_NAME			1
#define NFTA_TABLE_FLAGS		2
#endif
#ifndef NFTA_CHAIN_TABLE
#define NFTA_CHAIN_TABLE		1
#define NFTA_CHAIN_NAME			3
#define NFTA_CHAIN_HOOK			4
#define NFTA_CHAIN_TYPE			7
#endif
#ifndef NFTA_HOOK_HOOKNUM
#define NFTA_HOOK_HOOKNUM		1
#define NFTA_HOOK_PRIORITY		2
#define NFTA_HOOK_DEV			3
#define NFTA_HOOK_DEVS			4
#endif
#ifndef NFTA_RULE_TABLE
#define NFTA_RULE_TABLE			1
#define NFTA_RULE_CHAIN			2
#define NFTA_RULE_EXPRESSIONS		4
#endif
#ifndef NFTA_LIST_ELEM
#define NFTA_LIST_ELEM			1
#endif
#ifndef NFTA_EXPR_NAME
#define NFTA_EXPR_NAME			1
#define NFTA_EXPR_DATA			2
#endif
#ifndef NFTA_FLOWTABLE_TABLE
#define NFTA_FLOWTABLE_TABLE		1
#define NFTA_FLOWTABLE_NAME		2
#define NFTA_FLOWTABLE_HOOK		3
#endif
#ifndef NFTA_FLOWTABLE_HOOK_NUM
#define NFTA_FLOWTABLE_HOOK_NUM		1
#define NFTA_FLOWTABLE_HOOK_PRIORITY	2
#define NFTA_FLOWTABLE_HOOK_DEVS	3
#endif
#ifndef NFTA_DEVICE_NAME
#define NFTA_DEVICE_NAME		1
#endif
#ifndef NFTA_FLOW_TABLE_NAME
#define NFTA_FLOW_TABLE_NAME		1
#endif
