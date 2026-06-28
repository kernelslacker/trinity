#pragma once

/*
 * Wrapper around <linux/dev_energymodel.h> that ships the #ifndef-
 * guarded fallbacks for DEV_ENERGYMODEL_FAMILY_NAME / DEV_ENERGYMODEL_
 * FAMILY_VERSION and every DEV_ENERGYMODEL_CMD_* / DEV_ENERGYMODEL_A_*
 * id the grammar references.  Build hosts whose installed uapi predates
 * a given symbol silently miss it from the validator coverage; the
 * fallback values match the upstream uapi enum ordering so the wire-
 * format ids the kernel parses match the ones the message generator
 * emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <linux/dev_energymodel.h>)` gate, so the header itself can include
 * <linux/dev_energymodel.h> unconditionally.
 */
#include <linux/dev_energymodel.h>

#ifndef DEV_ENERGYMODEL_FAMILY_NAME
#define DEV_ENERGYMODEL_FAMILY_NAME		"dev-energymodel"
#endif
#ifndef DEV_ENERGYMODEL_FAMILY_VERSION
#define DEV_ENERGYMODEL_FAMILY_VERSION		1
#endif

#ifndef DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS
#define DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS	1
#endif
#ifndef DEV_ENERGYMODEL_CMD_GET_PERF_TABLE
#define DEV_ENERGYMODEL_CMD_GET_PERF_TABLE	2
#endif

#ifndef DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID
#define DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID	2
#endif
#ifndef DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID
#define DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID	1
#endif
