#pragma once

/*
 * Wrapper around <linux/netfilter/ipset/ip_set.h> that ships
 * #ifndef-guarded fallbacks for the ids added after the installed
 * uapi header.  Including <linux/netfilter/ipset/ip_set.h> here lets
 * a .c pull "kernel/ipset.h" once and get the real uapi enums plus
 * the fallback shims for ids the installed header is too old to
 * know.  Values are stable enum slots in ip_set.h; the fallbacks are
 * what the kernel has always assigned so an older-header build sees
 * the same on-wire numbers a newer-header build does.
 */
#include <linux/netfilter/ipset/ip_set.h>

#ifndef SO_IP_SET
#define SO_IP_SET		83
#endif

/*
 * Shims for CADT / create-only attrs added after the oldest build
 * host's uapi header.  MARK / MARKMASK were added for hash:mark;
 * BITMASK for the bitmask netmask work; INITVAL / BUCKETSIZE reused
 * the long-unused IPSET_ATTR_GC / IPSET_ATTR_PROBES slots.
 */
#ifndef IPSET_ATTR_CADT_LINENO
#define IPSET_ATTR_CADT_LINENO	9
#endif
#ifndef IPSET_ATTR_MARK
#define IPSET_ATTR_MARK		10
#endif
#ifndef IPSET_ATTR_MARKMASK
#define IPSET_ATTR_MARKMASK	11
#endif
#ifndef IPSET_ATTR_BITMASK
#define IPSET_ATTR_BITMASK	12
#endif
#ifndef IPSET_ATTR_INITVAL
#define IPSET_ATTR_INITVAL	17
#endif
#ifndef IPSET_ATTR_BUCKETSIZE
#define IPSET_ATTR_BUCKETSIZE	21
#endif

/*
 * ADT-namespace attrs — share numeric slots with the CREATE-only enum
 * (ETHER=17 collides with INITVAL=17, NAME=18 with HASHSIZE=18, etc.)
 * because the kernel matches by policy per nest, not by global id.
 */
#ifndef IPSET_ATTR_ETHER
#define IPSET_ATTR_ETHER	17
#endif
#ifndef IPSET_ATTR_NAME
#define IPSET_ATTR_NAME		18
#endif
#ifndef IPSET_ATTR_NAMEREF
#define IPSET_ATTR_NAMEREF	19
#endif
#ifndef IPSET_ATTR_IP2
#define IPSET_ATTR_IP2		20
#endif
#ifndef IPSET_ATTR_CIDR2
#define IPSET_ATTR_CIDR2	21
#endif
#ifndef IPSET_ATTR_IP2_TO
#define IPSET_ATTR_IP2_TO	22
#endif
#ifndef IPSET_ATTR_IFACE
#define IPSET_ATTR_IFACE	23
#endif

/* Inner IPSET_ATTR_IPADDR nested block. */
#ifndef IPSET_ATTR_IPADDR_IPV6
#define IPSET_ATTR_IPADDR_IPV6	2
#endif

/* IPSET_REVISION_MAX lives in the kernel-internal ip_set.h, not the
 * uapi header; ip_set_create_policy bounds REVISION with
 * NLA_POLICY_MAX(NLA_U8, IPSET_REVISION_MAX). */
#ifndef IPSET_REVISION_MAX
#define IPSET_REVISION_MAX	9
#endif
