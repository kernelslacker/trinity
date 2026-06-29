#pragma once

/*
 * Wrapper around <drm/drm_ras.h> that ships the #ifndef-guarded
 * fallbacks for DRM_RAS_FAMILY_NAME / DRM_RAS_FAMILY_VERSION and every
 * DRM_RAS_CMD_* / DRM_RAS_A_* id the grammar references.  Build hosts
 * whose installed uapi predates a given symbol silently miss it from
 * the validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the message generator emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <drm/drm_ras.h>)` gate, so the header itself can include
 * <drm/drm_ras.h> unconditionally.
 */
#include <drm/drm_ras.h>

#ifndef DRM_RAS_FAMILY_NAME
#define DRM_RAS_FAMILY_NAME		"drm-ras"
#endif
#ifndef DRM_RAS_FAMILY_VERSION
#define DRM_RAS_FAMILY_VERSION		1
#endif

#ifndef DRM_RAS_CMD_LIST_NODES
#define DRM_RAS_CMD_LIST_NODES			1
#endif
#ifndef DRM_RAS_CMD_GET_ERROR_COUNTER
#define DRM_RAS_CMD_GET_ERROR_COUNTER		2
#endif
#ifndef DRM_RAS_CMD_CLEAR_ERROR_COUNTER
#define DRM_RAS_CMD_CLEAR_ERROR_COUNTER		3
#endif

#ifndef DRM_RAS_A_NODE_ATTRS_NODE_ID
#define DRM_RAS_A_NODE_ATTRS_NODE_ID		1
#endif
#ifndef DRM_RAS_A_NODE_ATTRS_DEVICE_NAME
#define DRM_RAS_A_NODE_ATTRS_DEVICE_NAME	2
#endif
#ifndef DRM_RAS_A_NODE_ATTRS_NODE_NAME
#define DRM_RAS_A_NODE_ATTRS_NODE_NAME		3
#endif
#ifndef DRM_RAS_A_NODE_ATTRS_NODE_TYPE
#define DRM_RAS_A_NODE_ATTRS_NODE_TYPE		4
#endif

#ifndef DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID
#define DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID		1
#endif
#ifndef DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID
#define DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID		2
#endif
#ifndef DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME
#define DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME	3
#endif
#ifndef DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE
#define DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE	4
#endif
