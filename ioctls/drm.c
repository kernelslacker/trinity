
#ifdef USE_DRM

#include <inttypes.h>

#include <drm/drm.h>
#ifdef USE_DRM_EXYNOS
#include <drm/exynos_drm.h>
#endif
#include <drm/i915_drm.h>
#include <drm/nouveau_drm.h>
#include <drm/radeon_drm.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Copyright 2005 Stephane Marchesin.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
/*
 * Compile-time: sanitiser struct sizes must match _IOC_SIZE.  A
 * failure means the DRM UAPI moved and the memset(sizeof(*p)) below
 * is sizing against a stale struct definition -- fix the sanitiser,
 * do not silence the assert.  Only fixed-shape ioctls appear here;
 * ioctls whose arg is a pointer/scalar or a flex-tail struct are
 * skipped.
 */
_Static_assert(sizeof(struct drm_version) ==
	       _IOC_SIZE(DRM_IOCTL_VERSION),
	       "drm_version size vs DRM_IOCTL_VERSION mismatch");
_Static_assert(sizeof(struct drm_unique) ==
	       _IOC_SIZE(DRM_IOCTL_GET_UNIQUE),
	       "drm_unique size vs DRM_IOCTL_GET_UNIQUE mismatch");
_Static_assert(sizeof(struct drm_client) ==
	       _IOC_SIZE(DRM_IOCTL_GET_CLIENT),
	       "drm_client size vs DRM_IOCTL_GET_CLIENT mismatch");
_Static_assert(sizeof(struct drm_stats) ==
	       _IOC_SIZE(DRM_IOCTL_GET_STATS),
	       "drm_stats size vs DRM_IOCTL_GET_STATS mismatch");
#ifdef DRM_IOCTL_GET_CAP
_Static_assert(sizeof(struct drm_get_cap) ==
	       _IOC_SIZE(DRM_IOCTL_GET_CAP),
	       "drm_get_cap size vs DRM_IOCTL_GET_CAP mismatch");
#endif
#ifdef DRM_IOCTL_SET_CLIENT_CAP
_Static_assert(sizeof(struct drm_set_client_cap) ==
	       _IOC_SIZE(DRM_IOCTL_SET_CLIENT_CAP),
	       "drm_set_client_cap vs DRM_IOCTL_SET_CLIENT_CAP mismatch");
#endif
_Static_assert(sizeof(struct drm_mode_card_res) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETRESOURCES),
	       "drm_mode_card_res vs DRM_IOCTL_MODE_GETRESOURCES mismatch");
#ifdef DRM_IOCTL_MODE_GETPLANERESOURCES
_Static_assert(sizeof(struct drm_mode_get_plane_res) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETPLANERESOURCES),
	       "drm_mode_get_plane_res size vs _IOC_SIZE mismatch");
#endif
_Static_assert(sizeof(struct drm_mode_get_connector) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETCONNECTOR),
	       "drm_mode_get_connector size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct drm_mode_get_encoder) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETENCODER),
	       "drm_mode_get_encoder size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct drm_mode_crtc) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETCRTC),
	       "drm_mode_crtc size vs DRM_IOCTL_MODE_GETCRTC mismatch");
#ifdef DRM_IOCTL_MODE_GETPLANE
_Static_assert(sizeof(struct drm_mode_get_plane) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETPLANE),
	       "drm_mode_get_plane size vs _IOC_SIZE mismatch");
#endif
_Static_assert(sizeof(struct drm_mode_crtc_lut) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETGAMMA),
	       "drm_mode_crtc_lut size vs DRM_IOCTL_MODE_GETGAMMA mismatch");
_Static_assert(sizeof(struct drm_mode_get_property) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETPROPERTY),
	       "drm_mode_get_property size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct drm_mode_get_blob) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_GETPROPBLOB),
	       "drm_mode_get_blob size vs _IOC_SIZE mismatch");
#ifdef DRM_IOCTL_MODE_OBJ_GETPROPERTIES
_Static_assert(sizeof(struct drm_mode_obj_get_properties) ==
	       _IOC_SIZE(DRM_IOCTL_MODE_OBJ_GETPROPERTIES),
	       "drm_mode_obj_get_properties vs _IOC_SIZE mismatch");
#endif

#ifndef DRM_IOCTL_NOUVEAU_GETPARAM
struct drm_nouveau_getparam {
	uint64_t param;
	uint64_t value;
};
#define DRM_IOCTL_NOUVEAU_GETPARAM           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GETPARAM, struct drm_nouveau_getparam)
#endif

#ifndef DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC
struct drm_nouveau_channel_alloc {
	uint32_t     fb_ctxdma_handle;
	uint32_t     tt_ctxdma_handle;

	int          channel;
	uint32_t     pushbuf_domains;

	/* Notifier memory */
	uint32_t     notifier_handle;

	/* DRM-enforced subchannel assignments */
	struct {
		uint32_t handle;
		uint32_t grclass;
	} subchan[8];
	uint32_t nr_subchan;
};
#define DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC      DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_ALLOC, struct drm_nouveau_channel_alloc)
#endif

#ifndef DRM_IOCTL_NOUVEAU_CHANNEL_FREE
struct drm_nouveau_channel_free {
	int channel;
};
#define DRM_IOCTL_NOUVEAU_CHANNEL_FREE       DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_FREE, struct drm_nouveau_channel_free)
#endif

static const struct ioctl drm_ioctls[] = {
	/* drm/drm.h */
	IOCTL(DRM_IOCTL_VERSION),
	IOCTL(DRM_IOCTL_GET_UNIQUE),
	IOCTL(DRM_IOCTL_GET_MAGIC),
	IOCTL(DRM_IOCTL_IRQ_BUSID),
	IOCTL(DRM_IOCTL_GET_MAP),
	IOCTL(DRM_IOCTL_GET_CLIENT),
	IOCTL(DRM_IOCTL_GET_STATS),
	IOCTL(DRM_IOCTL_SET_VERSION),
	IOCTL(DRM_IOCTL_MODESET_CTL),
	IOCTL(DRM_IOCTL_GEM_CLOSE),
	IOCTL(DRM_IOCTL_GEM_FLINK),
	IOCTL(DRM_IOCTL_GEM_OPEN),
#ifdef DRM_IOCTL_GET_CAP
	IOCTL(DRM_IOCTL_GET_CAP),
#endif
	IOCTL(DRM_IOCTL_SET_UNIQUE),
	IOCTL(DRM_IOCTL_AUTH_MAGIC),
	IOCTL(DRM_IOCTL_BLOCK),
	IOCTL(DRM_IOCTL_UNBLOCK),
	IOCTL(DRM_IOCTL_CONTROL),
	IOCTL(DRM_IOCTL_ADD_MAP),
	IOCTL(DRM_IOCTL_ADD_BUFS),
	IOCTL(DRM_IOCTL_MARK_BUFS),
	IOCTL(DRM_IOCTL_INFO_BUFS),
	IOCTL(DRM_IOCTL_MAP_BUFS),
	IOCTL(DRM_IOCTL_FREE_BUFS),
	IOCTL(DRM_IOCTL_RM_MAP),
	IOCTL(DRM_IOCTL_SET_SAREA_CTX),
	IOCTL(DRM_IOCTL_GET_SAREA_CTX),
	IOCTL(DRM_IOCTL_SET_MASTER),
	IOCTL(DRM_IOCTL_DROP_MASTER),
	IOCTL(DRM_IOCTL_ADD_CTX),
	IOCTL(DRM_IOCTL_RM_CTX),
	IOCTL(DRM_IOCTL_MOD_CTX),
	IOCTL(DRM_IOCTL_GET_CTX),
	IOCTL(DRM_IOCTL_SWITCH_CTX),
	IOCTL(DRM_IOCTL_NEW_CTX),
	IOCTL(DRM_IOCTL_RES_CTX),
	IOCTL(DRM_IOCTL_ADD_DRAW),
	IOCTL(DRM_IOCTL_RM_DRAW),
	IOCTL(DRM_IOCTL_DMA),
	IOCTL(DRM_IOCTL_LOCK),
	IOCTL(DRM_IOCTL_UNLOCK),
	IOCTL(DRM_IOCTL_FINISH),
#ifdef DRM_IOCTL_PRIME_HANDLE_TO_FD
	IOCTL(DRM_IOCTL_PRIME_HANDLE_TO_FD),
#endif
#ifdef DRM_IOCTL_PRIME_FD_TO_HANDLE
	IOCTL(DRM_IOCTL_PRIME_FD_TO_HANDLE),
#endif
	IOCTL(DRM_IOCTL_AGP_ACQUIRE),
	IOCTL(DRM_IOCTL_AGP_RELEASE),
	IOCTL(DRM_IOCTL_AGP_ENABLE),
	IOCTL(DRM_IOCTL_AGP_INFO),
	IOCTL(DRM_IOCTL_AGP_ALLOC),
	IOCTL(DRM_IOCTL_AGP_FREE),
	IOCTL(DRM_IOCTL_AGP_BIND),
	IOCTL(DRM_IOCTL_AGP_UNBIND),
	IOCTL(DRM_IOCTL_SG_ALLOC),
	IOCTL(DRM_IOCTL_SG_FREE),
	IOCTL(DRM_IOCTL_WAIT_VBLANK),
	IOCTL(DRM_IOCTL_UPDATE_DRAW),
	IOCTL(DRM_IOCTL_MODE_GETRESOURCES),
	IOCTL(DRM_IOCTL_MODE_GETCRTC),
	IOCTL(DRM_IOCTL_MODE_SETCRTC),
	IOCTL(DRM_IOCTL_MODE_CURSOR),
	IOCTL(DRM_IOCTL_MODE_GETGAMMA),
	IOCTL(DRM_IOCTL_MODE_SETGAMMA),
	IOCTL(DRM_IOCTL_MODE_GETENCODER),
	IOCTL(DRM_IOCTL_MODE_GETCONNECTOR),
	IOCTL(DRM_IOCTL_MODE_ATTACHMODE),
	IOCTL(DRM_IOCTL_MODE_DETACHMODE),
	IOCTL(DRM_IOCTL_MODE_GETPROPERTY),
	IOCTL(DRM_IOCTL_MODE_SETPROPERTY),
	IOCTL(DRM_IOCTL_MODE_GETPROPBLOB),
	IOCTL(DRM_IOCTL_MODE_GETFB),
	IOCTL(DRM_IOCTL_MODE_ADDFB),
	IOCTL(DRM_IOCTL_MODE_RMFB),
	IOCTL(DRM_IOCTL_MODE_PAGE_FLIP),
	IOCTL(DRM_IOCTL_MODE_DIRTYFB),
#ifdef DRM_IOCTL_MODE_CREATE_DUMB
	IOCTL(DRM_IOCTL_MODE_CREATE_DUMB),
#endif
#ifdef DRM_IOCTL_MODE_MAP_DUMB
	IOCTL(DRM_IOCTL_MODE_MAP_DUMB),
#endif
#ifdef DRM_IOCTL_MODE_DESTROY_DUMB
	IOCTL(DRM_IOCTL_MODE_DESTROY_DUMB),
#endif
#ifdef DRM_IOCTL_MODE_GETPLANERESOURCES
	IOCTL(DRM_IOCTL_MODE_GETPLANERESOURCES),
#endif
#ifdef DRM_IOCTL_MODE_GETPLANE
	IOCTL(DRM_IOCTL_MODE_GETPLANE),
#endif
#ifdef DRM_IOCTL_MODE_SETPLANE
	IOCTL(DRM_IOCTL_MODE_SETPLANE),
#endif
#ifdef DRM_IOCTL_MODE_ADDFB2
	IOCTL(DRM_IOCTL_MODE_ADDFB2),
#endif
#ifdef DRM_IOCTL_MODE_OBJ_GETPROPERTIES
	IOCTL(DRM_IOCTL_MODE_OBJ_GETPROPERTIES),
#endif
#ifdef DRM_IOCTL_MODE_OBJ_SETPROPERTY
	IOCTL(DRM_IOCTL_MODE_OBJ_SETPROPERTY),
#endif
#ifdef DRM_IOCTL_SET_CLIENT_CAP
	IOCTL(DRM_IOCTL_SET_CLIENT_CAP),
#endif
#ifdef DRM_IOCTL_MODE_CURSOR2
	IOCTL(DRM_IOCTL_MODE_CURSOR2),
#endif
#ifdef DRM_IOCTL_MODE_ATOMIC
	IOCTL(DRM_IOCTL_MODE_ATOMIC),
#endif
#ifdef DRM_IOCTL_MODE_CREATEPROPBLOB
	IOCTL(DRM_IOCTL_MODE_CREATEPROPBLOB),
#endif
#ifdef DRM_IOCTL_MODE_DESTROYPROPBLOB
	IOCTL(DRM_IOCTL_MODE_DESTROYPROPBLOB),
#endif
#ifdef DRM_IOCTL_MODE_GETFB2
	IOCTL(DRM_IOCTL_MODE_GETFB2),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_CREATE
	IOCTL(DRM_IOCTL_SYNCOBJ_CREATE),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_DESTROY
	IOCTL(DRM_IOCTL_SYNCOBJ_DESTROY),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD
	IOCTL(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE
	IOCTL(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_WAIT
	IOCTL(DRM_IOCTL_SYNCOBJ_WAIT),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_RESET
	IOCTL(DRM_IOCTL_SYNCOBJ_RESET),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_SIGNAL
	IOCTL(DRM_IOCTL_SYNCOBJ_SIGNAL),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT
	IOCTL(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_QUERY
	IOCTL(DRM_IOCTL_SYNCOBJ_QUERY),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_TRANSFER
	IOCTL(DRM_IOCTL_SYNCOBJ_TRANSFER),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL
	IOCTL(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL),
#endif
#ifdef DRM_IOCTL_SYNCOBJ_EVENTFD
	IOCTL(DRM_IOCTL_SYNCOBJ_EVENTFD),
#endif
#ifdef DRM_IOCTL_MODE_CREATE_LEASE
	IOCTL(DRM_IOCTL_MODE_CREATE_LEASE),
#endif
#ifdef DRM_IOCTL_MODE_LIST_LESSEES
	IOCTL(DRM_IOCTL_MODE_LIST_LESSEES),
#endif
#ifdef DRM_IOCTL_MODE_GET_LEASE
	IOCTL(DRM_IOCTL_MODE_GET_LEASE),
#endif
#ifdef DRM_IOCTL_MODE_REVOKE_LEASE
	IOCTL(DRM_IOCTL_MODE_REVOKE_LEASE),
#endif
#ifdef DRM_IOCTL_CRTC_GET_SEQUENCE
	IOCTL(DRM_IOCTL_CRTC_GET_SEQUENCE),
#endif
#ifdef DRM_IOCTL_CRTC_QUEUE_SEQUENCE
	IOCTL(DRM_IOCTL_CRTC_QUEUE_SEQUENCE),
#endif
#ifdef DRM_IOCTL_MODE_CLOSEFB
	IOCTL(DRM_IOCTL_MODE_CLOSEFB),
#endif
#ifdef DRM_IOCTL_SET_CLIENT_NAME
	IOCTL(DRM_IOCTL_SET_CLIENT_NAME),
#endif

#ifdef USE_DRM_EXYNOS
	/* exynos_drm.h */
	IOCTL(DRM_IOCTL_EXYNOS_GEM_CREATE),
#ifdef DRM_IOCTL_EXYNOS_GEM_MAP_OFFSET
	IOCTL(DRM_IOCTL_EXYNOS_GEM_MAP_OFFSET),
#endif
#ifdef DRM_IOCTL_EXYNOS_GEM_MMAP
	IOCTL(DRM_IOCTL_EXYNOS_GEM_MMAP),
#endif
#ifdef DRM_IOCTL_EXYNOS_GEM_GET
	IOCTL(DRM_IOCTL_EXYNOS_GEM_GET),
#endif
#ifdef DRM_IOCTL_EXYNOS_VIDI_CONNECTION
	IOCTL(DRM_IOCTL_EXYNOS_VIDI_CONNECTION),
#endif
#ifdef DRM_IOCTL_EXYNOS_G2D_GET_VER
	IOCTL(DRM_IOCTL_EXYNOS_G2D_GET_VER),
#endif
#ifdef DRM_IOCTL_EXYNOS_G2D_SET_CMDLIST
	IOCTL(DRM_IOCTL_EXYNOS_G2D_SET_CMDLIST),
#endif
#ifdef DRM_IOCTL_EXYNOS_G2D_EXEC
	IOCTL(DRM_IOCTL_EXYNOS_G2D_EXEC),
#endif
#endif

	/* i915_drm.h */
	IOCTL(DRM_IOCTL_I915_INIT),
	IOCTL(DRM_IOCTL_I915_FLUSH),
	IOCTL(DRM_IOCTL_I915_FLIP),
	IOCTL(DRM_IOCTL_I915_BATCHBUFFER),
	IOCTL(DRM_IOCTL_I915_IRQ_EMIT),
	IOCTL(DRM_IOCTL_I915_IRQ_WAIT),
	IOCTL(DRM_IOCTL_I915_GETPARAM),
	IOCTL(DRM_IOCTL_I915_SETPARAM),
	IOCTL(DRM_IOCTL_I915_ALLOC),
	IOCTL(DRM_IOCTL_I915_FREE),
	IOCTL(DRM_IOCTL_I915_INIT_HEAP),
	IOCTL(DRM_IOCTL_I915_CMDBUFFER),
	IOCTL(DRM_IOCTL_I915_DESTROY_HEAP),
	IOCTL(DRM_IOCTL_I915_SET_VBLANK_PIPE),
	IOCTL(DRM_IOCTL_I915_GET_VBLANK_PIPE),
	IOCTL(DRM_IOCTL_I915_VBLANK_SWAP),
#ifdef DRM_IOCTL_I915_HWS_ADDR
	IOCTL(DRM_IOCTL_I915_HWS_ADDR),
#endif
	IOCTL(DRM_IOCTL_I915_GEM_INIT),
	IOCTL(DRM_IOCTL_I915_GEM_EXECBUFFER),
	IOCTL(DRM_IOCTL_I915_GEM_EXECBUFFER2),
	IOCTL(DRM_IOCTL_I915_GEM_PIN),
	IOCTL(DRM_IOCTL_I915_GEM_UNPIN),
	IOCTL(DRM_IOCTL_I915_GEM_BUSY),
#ifdef DRM_IOCTL_I915_GEM_SET_CACHING
	IOCTL(DRM_IOCTL_I915_GEM_SET_CACHING),
#endif
#ifdef DRM_IOCTL_I915_GEM_GET_CACHING
	IOCTL(DRM_IOCTL_I915_GEM_GET_CACHING),
#endif
	IOCTL(DRM_IOCTL_I915_GEM_THROTTLE),
	IOCTL(DRM_IOCTL_I915_GEM_ENTERVT),
	IOCTL(DRM_IOCTL_I915_GEM_LEAVEVT),
	IOCTL(DRM_IOCTL_I915_GEM_CREATE),
	IOCTL(DRM_IOCTL_I915_GEM_PREAD),
	IOCTL(DRM_IOCTL_I915_GEM_PWRITE),
	IOCTL(DRM_IOCTL_I915_GEM_MMAP),
	IOCTL(DRM_IOCTL_I915_GEM_MMAP_GTT),
	IOCTL(DRM_IOCTL_I915_GEM_SET_DOMAIN),
	IOCTL(DRM_IOCTL_I915_GEM_SW_FINISH),
	IOCTL(DRM_IOCTL_I915_GEM_SET_TILING),
	IOCTL(DRM_IOCTL_I915_GEM_GET_TILING),
	IOCTL(DRM_IOCTL_I915_GEM_GET_APERTURE),
	IOCTL(DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID),
	IOCTL(DRM_IOCTL_I915_GEM_MADVISE),
	IOCTL(DRM_IOCTL_I915_OVERLAY_PUT_IMAGE),
	IOCTL(DRM_IOCTL_I915_OVERLAY_ATTRS),
#ifdef DRM_IOCTL_I915_SET_SPRITE_COLORKEY
	IOCTL(DRM_IOCTL_I915_SET_SPRITE_COLORKEY),
#endif
#ifdef DRM_IOCTL_I915_GET_SPRITE_COLORKEY
	IOCTL(DRM_IOCTL_I915_GET_SPRITE_COLORKEY),
#endif
#ifdef DRM_IOCTL_I915_GEM_WAIT
	IOCTL(DRM_IOCTL_I915_GEM_WAIT),
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_CREATE
	IOCTL(DRM_IOCTL_I915_GEM_CONTEXT_CREATE),
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_DESTROY
	IOCTL(DRM_IOCTL_I915_GEM_CONTEXT_DESTROY),
#endif
#ifdef DRM_IOCTL_I915_REG_READ
	IOCTL(DRM_IOCTL_I915_REG_READ),
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM
	IOCTL(DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM),
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM
	IOCTL(DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM),
#endif
#ifdef DRM_IOCTL_I915_GEM_EXECBUFFER2_WR
	IOCTL(DRM_IOCTL_I915_GEM_EXECBUFFER2_WR),
#endif
#ifdef DRM_IOCTL_I915_GEM_MMAP_OFFSET
	IOCTL(DRM_IOCTL_I915_GEM_MMAP_OFFSET),
#endif
#ifdef DRM_IOCTL_I915_QUERY
	IOCTL(DRM_IOCTL_I915_QUERY),
#endif
#ifdef DRM_IOCTL_I915_PERF_OPEN
	IOCTL(DRM_IOCTL_I915_PERF_OPEN),
#endif
#ifdef DRM_IOCTL_I915_PERF_ADD_CONFIG
	IOCTL(DRM_IOCTL_I915_PERF_ADD_CONFIG),
#endif
#ifdef DRM_IOCTL_I915_PERF_REMOVE_CONFIG
	IOCTL(DRM_IOCTL_I915_PERF_REMOVE_CONFIG),
#endif

	/* nouveau_drm.h */
	IOCTL(DRM_IOCTL_NOUVEAU_GETPARAM),
	IOCTL(DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC),
	IOCTL(DRM_IOCTL_NOUVEAU_CHANNEL_FREE),
#ifdef DRM_IOCTL_NOUVEAU_GEM_NEW
	IOCTL(DRM_IOCTL_NOUVEAU_GEM_NEW),
#endif
#ifdef DRM_IOCTL_NOUVEAU_GEM_PUSHBUF
	IOCTL(DRM_IOCTL_NOUVEAU_GEM_PUSHBUF),
#endif
#ifdef DRM_IOCTL_NOUVEAU_GEM_CPU_PREP
	IOCTL(DRM_IOCTL_NOUVEAU_GEM_CPU_PREP),
#endif
#ifdef DRM_IOCTL_NOUVEAU_GEM_CPU_FINI
	IOCTL(DRM_IOCTL_NOUVEAU_GEM_CPU_FINI),
#endif
#ifdef DRM_IOCTL_NOUVEAU_GEM_INFO
	IOCTL(DRM_IOCTL_NOUVEAU_GEM_INFO),
#endif

	/* radeon_drm.h */
	IOCTL(DRM_IOCTL_RADEON_CP_INIT),
	IOCTL(DRM_IOCTL_RADEON_CP_START),
	IOCTL(DRM_IOCTL_RADEON_CP_STOP),
	IOCTL(DRM_IOCTL_RADEON_CP_RESET),
	IOCTL(DRM_IOCTL_RADEON_CP_IDLE),
	IOCTL(DRM_IOCTL_RADEON_RESET),
	IOCTL(DRM_IOCTL_RADEON_FULLSCREEN),
	IOCTL(DRM_IOCTL_RADEON_SWAP),
	IOCTL(DRM_IOCTL_RADEON_CLEAR),
	IOCTL(DRM_IOCTL_RADEON_VERTEX),
	IOCTL(DRM_IOCTL_RADEON_INDICES),
	IOCTL(DRM_IOCTL_RADEON_STIPPLE),
	IOCTL(DRM_IOCTL_RADEON_INDIRECT),
	IOCTL(DRM_IOCTL_RADEON_TEXTURE),
	IOCTL(DRM_IOCTL_RADEON_VERTEX2),
	IOCTL(DRM_IOCTL_RADEON_CMDBUF),
	IOCTL(DRM_IOCTL_RADEON_GETPARAM),
	IOCTL(DRM_IOCTL_RADEON_FLIP),
	IOCTL(DRM_IOCTL_RADEON_ALLOC),
	IOCTL(DRM_IOCTL_RADEON_FREE),
	IOCTL(DRM_IOCTL_RADEON_INIT_HEAP),
	IOCTL(DRM_IOCTL_RADEON_IRQ_EMIT),
	IOCTL(DRM_IOCTL_RADEON_IRQ_WAIT),
	IOCTL(DRM_IOCTL_RADEON_CP_RESUME),
	IOCTL(DRM_IOCTL_RADEON_SETPARAM),
	IOCTL(DRM_IOCTL_RADEON_SURF_ALLOC),
	IOCTL(DRM_IOCTL_RADEON_SURF_FREE),
	IOCTL(DRM_IOCTL_RADEON_GEM_INFO),
	IOCTL(DRM_IOCTL_RADEON_GEM_CREATE),
	IOCTL(DRM_IOCTL_RADEON_GEM_MMAP),
	IOCTL(DRM_IOCTL_RADEON_GEM_PREAD),
	IOCTL(DRM_IOCTL_RADEON_GEM_PWRITE),
	IOCTL(DRM_IOCTL_RADEON_GEM_SET_DOMAIN),
	IOCTL(DRM_IOCTL_RADEON_GEM_WAIT_IDLE),
	IOCTL(DRM_IOCTL_RADEON_CS),
	IOCTL(DRM_IOCTL_RADEON_INFO),
#ifdef DRM_IOCTL_RADEON_GEM_SET_TILING
	IOCTL(DRM_IOCTL_RADEON_GEM_SET_TILING),
#endif
#ifdef DRM_IOCTL_RADEON_GEM_GET_TILING
	IOCTL(DRM_IOCTL_RADEON_GEM_GET_TILING),
#endif
	IOCTL(DRM_IOCTL_RADEON_GEM_BUSY),
#ifdef DRM_IOCTL_RADEON_GEM_VA
	IOCTL(DRM_IOCTL_RADEON_GEM_VA),
#endif
};

static const char *const drm_devs[] = {
	"drm",
};

static void drm_sanitise_version(struct syscallrecord *rec)
{
	struct drm_version *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

#ifdef DRM_IOCTL_GET_CAP
static void drm_sanitise_get_cap(struct syscallrecord *rec)
{
	static const __u64 caps[] = {
		DRM_CAP_DUMB_BUFFER,
		DRM_CAP_VBLANK_HIGH_CRTC,
		DRM_CAP_DUMB_PREFERRED_DEPTH,
		DRM_CAP_DUMB_PREFER_SHADOW,
		DRM_CAP_PRIME,
		DRM_CAP_TIMESTAMP_MONOTONIC,
		DRM_CAP_ASYNC_PAGE_FLIP,
		DRM_CAP_CURSOR_WIDTH,
		DRM_CAP_CURSOR_HEIGHT,
		DRM_CAP_ADDFB2_MODIFIERS,
	};
	struct drm_get_cap *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->capability = RAND_ARRAY(caps);
	rec->a3 = (unsigned long) p;
}
#endif

static void drm_sanitise_get_client(struct syscallrecord *rec)
{
	struct drm_client *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->idx = rnd_modulo_u32(8);
	rec->a3 = (unsigned long) p;
}

#ifdef DRM_IOCTL_SET_CLIENT_CAP
static void drm_sanitise_set_client_cap(struct syscallrecord *rec)
{
	static const __u64 client_caps[] = {
		DRM_CLIENT_CAP_STEREO_3D,
		DRM_CLIENT_CAP_UNIVERSAL_PLANES,
		DRM_CLIENT_CAP_ATOMIC,
		DRM_CLIENT_CAP_ASPECT_RATIO,
		DRM_CLIENT_CAP_WRITEBACK_CONNECTORS,
	};
	struct drm_set_client_cap *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->capability = RAND_ARRAY(client_caps);
	p->value = RAND_BOOL();
	rec->a3 = (unsigned long) p;
}
#endif

static void drm_sanitise_mode_getresources(struct syscallrecord *rec)
{
	struct drm_mode_card_res *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

#ifdef DRM_IOCTL_MODE_GETPLANERESOURCES
static void drm_sanitise_mode_getplaneresources(struct syscallrecord *rec)
{
	struct drm_mode_get_plane_res *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}
#endif

static void drm_sanitise_mode_getconnector(struct syscallrecord *rec)
{
	struct drm_mode_get_connector *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->connector_id = rnd_modulo_u32(64);
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_mode_getencoder(struct syscallrecord *rec)
{
	struct drm_mode_get_encoder *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->encoder_id = rnd_modulo_u32(64);
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_mode_getcrtc(struct syscallrecord *rec)
{
	struct drm_mode_crtc *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->crtc_id = rnd_modulo_u32(64);
	rec->a3 = (unsigned long) p;
}

#ifdef DRM_IOCTL_MODE_GETPLANE
static void drm_sanitise_mode_getplane(struct syscallrecord *rec)
{
	struct drm_mode_get_plane *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->plane_id = rnd_modulo_u32(64);
	rec->a3 = (unsigned long) p;
}
#endif

static void drm_sanitise_get_unique(struct syscallrecord *rec)
{
	struct drm_unique *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->unique_len = 0;
	p->unique = NULL;
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_get_stats(struct syscallrecord *rec)
{
	struct drm_stats *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_mode_getgamma(struct syscallrecord *rec)
{
	struct drm_mode_crtc_lut *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->crtc_id = rnd_modulo_u32(64);
	p->gamma_size = 0;
	p->red = 0;
	p->green = 0;
	p->blue = 0;
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_mode_getproperty(struct syscallrecord *rec)
{
	struct drm_mode_get_property *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->prop_id = rnd_modulo_u32(128);
	p->count_values = 0;
	p->count_enum_blobs = 0;
	p->values_ptr = 0;
	p->enum_blob_ptr = 0;
	rec->a3 = (unsigned long) p;
}

static void drm_sanitise_mode_getpropblob(struct syscallrecord *rec)
{
	struct drm_mode_get_blob *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->blob_id = rnd_modulo_u32(128);
	p->length = 0;
	p->data = 0;
	rec->a3 = (unsigned long) p;
}

#ifdef DRM_IOCTL_MODE_OBJ_GETPROPERTIES
static void drm_sanitise_mode_obj_getproperties(struct syscallrecord *rec)
{
	static const __u32 obj_types[] = {
		DRM_MODE_OBJECT_CRTC,
		DRM_MODE_OBJECT_CONNECTOR,
		DRM_MODE_OBJECT_ENCODER,
		DRM_MODE_OBJECT_MODE,
		DRM_MODE_OBJECT_PROPERTY,
		DRM_MODE_OBJECT_FB,
		DRM_MODE_OBJECT_BLOB,
		DRM_MODE_OBJECT_PLANE,
	};
	struct drm_mode_obj_get_properties *p = get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->obj_id = rnd_modulo_u32(64);
	p->obj_type = RAND_ARRAY(obj_types);
	p->count_props = 0;
	p->props_ptr = 0;
	p->prop_values_ptr = 0;
	rec->a3 = (unsigned long) p;
}
#endif

static void drm_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case DRM_IOCTL_VERSION:
		drm_sanitise_version(rec);
		break;

#ifdef DRM_IOCTL_GET_CAP
	case DRM_IOCTL_GET_CAP:
		drm_sanitise_get_cap(rec);
		break;
#endif

	case DRM_IOCTL_GET_CLIENT:
		drm_sanitise_get_client(rec);
		break;

#ifdef DRM_IOCTL_SET_CLIENT_CAP
	case DRM_IOCTL_SET_CLIENT_CAP:
		drm_sanitise_set_client_cap(rec);
		break;
#endif

	case DRM_IOCTL_MODE_GETRESOURCES:
		drm_sanitise_mode_getresources(rec);
		break;

#ifdef DRM_IOCTL_MODE_GETPLANERESOURCES
	case DRM_IOCTL_MODE_GETPLANERESOURCES:
		drm_sanitise_mode_getplaneresources(rec);
		break;
#endif

	case DRM_IOCTL_MODE_GETCONNECTOR:
		drm_sanitise_mode_getconnector(rec);
		break;

	case DRM_IOCTL_MODE_GETENCODER:
		drm_sanitise_mode_getencoder(rec);
		break;

	case DRM_IOCTL_MODE_GETCRTC:
		drm_sanitise_mode_getcrtc(rec);
		break;

#ifdef DRM_IOCTL_MODE_GETPLANE
	case DRM_IOCTL_MODE_GETPLANE:
		drm_sanitise_mode_getplane(rec);
		break;
#endif

	case DRM_IOCTL_GET_UNIQUE:
		drm_sanitise_get_unique(rec);
		break;

	case DRM_IOCTL_GET_STATS:
		drm_sanitise_get_stats(rec);
		break;

	case DRM_IOCTL_MODE_GETGAMMA:
		drm_sanitise_mode_getgamma(rec);
		break;

	case DRM_IOCTL_MODE_GETPROPERTY:
		drm_sanitise_mode_getproperty(rec);
		break;

	case DRM_IOCTL_MODE_GETPROPBLOB:
		drm_sanitise_mode_getpropblob(rec);
		break;

#ifdef DRM_IOCTL_MODE_OBJ_GETPROPERTIES
	case DRM_IOCTL_MODE_OBJ_GETPROPERTIES:
		drm_sanitise_mode_obj_getproperties(rec);
		break;
#endif

	default:
		break;
	}
}

static const struct ioctl_group drm_grp = {
	.devtype = DEV_CHAR,
	.devs = drm_devs,
	.devs_cnt = ARRAY_SIZE(drm_devs),
	.sanitise = drm_sanitise,
	.ioctls = drm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(drm_ioctls),
};

REG_IOCTL_GROUP(drm_grp)

#endif /* USE_DRM */
