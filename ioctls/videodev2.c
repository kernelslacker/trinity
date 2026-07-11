#include <linux/videodev2.h>

#include "utils.h"
#include "ioctls.h"

/*
 * Compile-time: every fixed-shape v4l2 ioctl command in the table
 * below whose arg is a kernel struct must have sizeof(struct)
 * matching the _IOC_SIZE encoded in its request bits.  A mismatch
 * means videodev2.h moved under us and the request bits now encode a
 * different struct than we're passing (or vice versa) -- either
 * short of the kernel's copy_from_user() / copy_to_user() or past
 * it.  Commands sharing a struct (VIDIOC_G_FMT / VIDIOC_S_FMT /
 * VIDIOC_TRY_FMT all take v4l2_format; VIDIOC_QUERYBUF / VIDIOC_QBUF
 * / VIDIOC_DQBUF / VIDIOC_PREPARE_BUF all take v4l2_buffer; and so
 * on for the other _G / _S / _TRY / _ENUM / _CMD families below) get
 * one assert each -- the sides can drift independently in a header
 * refactor.  Per-cmd #ifdef guards mirror the ioctl-table wrapping
 * so builds against older uapi headers that predate a command still
 * compile.
 *
 * VIDIOC_OVERLAY, VIDIOC_STREAMON, VIDIOC_STREAMOFF, VIDIOC_G_INPUT,
 * VIDIOC_S_INPUT, VIDIOC_G_OUTPUT, VIDIOC_S_OUTPUT encode a bare
 * int; VIDIOC_G_STD, VIDIOC_S_STD and VIDIOC_QUERYSTD encode
 * v4l2_std_id (a bare __u64); VIDIOC_G_PRIORITY and
 * VIDIOC_S_PRIORITY encode a bare __u32; VIDIOC_LOG_STATUS is _IO()
 * with no arg.  All are intentionally absent -- asserting
 * sizeof(struct) against a scalar or a zero _IOC_SIZE would be the
 * wrong shape of check.
 */
_Static_assert(sizeof(struct v4l2_capability) ==
	       _IOC_SIZE(VIDIOC_QUERYCAP),
	       "v4l2_capability size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_fmtdesc) ==
	       _IOC_SIZE(VIDIOC_ENUM_FMT),
	       "v4l2_fmtdesc size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_format) ==
	       _IOC_SIZE(VIDIOC_G_FMT),
	       "v4l2_format size vs VIDIOC_G_FMT mismatch");
_Static_assert(sizeof(struct v4l2_format) ==
	       _IOC_SIZE(VIDIOC_S_FMT),
	       "v4l2_format size vs VIDIOC_S_FMT mismatch");
_Static_assert(sizeof(struct v4l2_format) ==
	       _IOC_SIZE(VIDIOC_TRY_FMT),
	       "v4l2_format size vs VIDIOC_TRY_FMT mismatch");
_Static_assert(sizeof(struct v4l2_requestbuffers) ==
	       _IOC_SIZE(VIDIOC_REQBUFS),
	       "v4l2_requestbuffers size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_buffer) ==
	       _IOC_SIZE(VIDIOC_QUERYBUF),
	       "v4l2_buffer size vs VIDIOC_QUERYBUF mismatch");
_Static_assert(sizeof(struct v4l2_buffer) ==
	       _IOC_SIZE(VIDIOC_QBUF),
	       "v4l2_buffer size vs VIDIOC_QBUF mismatch");
_Static_assert(sizeof(struct v4l2_buffer) ==
	       _IOC_SIZE(VIDIOC_DQBUF),
	       "v4l2_buffer size vs VIDIOC_DQBUF mismatch");
_Static_assert(sizeof(struct v4l2_framebuffer) ==
	       _IOC_SIZE(VIDIOC_G_FBUF),
	       "v4l2_framebuffer size vs VIDIOC_G_FBUF mismatch");
_Static_assert(sizeof(struct v4l2_framebuffer) ==
	       _IOC_SIZE(VIDIOC_S_FBUF),
	       "v4l2_framebuffer size vs VIDIOC_S_FBUF mismatch");
#ifdef VIDIOC_EXPBUF
_Static_assert(sizeof(struct v4l2_exportbuffer) ==
	       _IOC_SIZE(VIDIOC_EXPBUF),
	       "v4l2_exportbuffer size vs _IOC_SIZE mismatch");
#endif
_Static_assert(sizeof(struct v4l2_streamparm) ==
	       _IOC_SIZE(VIDIOC_G_PARM),
	       "v4l2_streamparm size vs VIDIOC_G_PARM mismatch");
_Static_assert(sizeof(struct v4l2_streamparm) ==
	       _IOC_SIZE(VIDIOC_S_PARM),
	       "v4l2_streamparm size vs VIDIOC_S_PARM mismatch");
_Static_assert(sizeof(struct v4l2_standard) ==
	       _IOC_SIZE(VIDIOC_ENUMSTD),
	       "v4l2_standard size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_input) ==
	       _IOC_SIZE(VIDIOC_ENUMINPUT),
	       "v4l2_input size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_control) ==
	       _IOC_SIZE(VIDIOC_G_CTRL),
	       "v4l2_control size vs VIDIOC_G_CTRL mismatch");
_Static_assert(sizeof(struct v4l2_control) ==
	       _IOC_SIZE(VIDIOC_S_CTRL),
	       "v4l2_control size vs VIDIOC_S_CTRL mismatch");
_Static_assert(sizeof(struct v4l2_tuner) ==
	       _IOC_SIZE(VIDIOC_G_TUNER),
	       "v4l2_tuner size vs VIDIOC_G_TUNER mismatch");
_Static_assert(sizeof(struct v4l2_tuner) ==
	       _IOC_SIZE(VIDIOC_S_TUNER),
	       "v4l2_tuner size vs VIDIOC_S_TUNER mismatch");
_Static_assert(sizeof(struct v4l2_audio) ==
	       _IOC_SIZE(VIDIOC_G_AUDIO),
	       "v4l2_audio size vs VIDIOC_G_AUDIO mismatch");
_Static_assert(sizeof(struct v4l2_audio) ==
	       _IOC_SIZE(VIDIOC_S_AUDIO),
	       "v4l2_audio size vs VIDIOC_S_AUDIO mismatch");
_Static_assert(sizeof(struct v4l2_queryctrl) ==
	       _IOC_SIZE(VIDIOC_QUERYCTRL),
	       "v4l2_queryctrl size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_querymenu) ==
	       _IOC_SIZE(VIDIOC_QUERYMENU),
	       "v4l2_querymenu size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_output) ==
	       _IOC_SIZE(VIDIOC_ENUMOUTPUT),
	       "v4l2_output size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_audioout) ==
	       _IOC_SIZE(VIDIOC_G_AUDOUT),
	       "v4l2_audioout size vs VIDIOC_G_AUDOUT mismatch");
_Static_assert(sizeof(struct v4l2_audioout) ==
	       _IOC_SIZE(VIDIOC_S_AUDOUT),
	       "v4l2_audioout size vs VIDIOC_S_AUDOUT mismatch");
_Static_assert(sizeof(struct v4l2_modulator) ==
	       _IOC_SIZE(VIDIOC_G_MODULATOR),
	       "v4l2_modulator size vs VIDIOC_G_MODULATOR mismatch");
_Static_assert(sizeof(struct v4l2_modulator) ==
	       _IOC_SIZE(VIDIOC_S_MODULATOR),
	       "v4l2_modulator size vs VIDIOC_S_MODULATOR mismatch");
_Static_assert(sizeof(struct v4l2_frequency) ==
	       _IOC_SIZE(VIDIOC_G_FREQUENCY),
	       "v4l2_frequency size vs VIDIOC_G_FREQUENCY mismatch");
_Static_assert(sizeof(struct v4l2_frequency) ==
	       _IOC_SIZE(VIDIOC_S_FREQUENCY),
	       "v4l2_frequency size vs VIDIOC_S_FREQUENCY mismatch");
_Static_assert(sizeof(struct v4l2_cropcap) ==
	       _IOC_SIZE(VIDIOC_CROPCAP),
	       "v4l2_cropcap size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_crop) ==
	       _IOC_SIZE(VIDIOC_G_CROP),
	       "v4l2_crop size vs VIDIOC_G_CROP mismatch");
_Static_assert(sizeof(struct v4l2_crop) ==
	       _IOC_SIZE(VIDIOC_S_CROP),
	       "v4l2_crop size vs VIDIOC_S_CROP mismatch");
_Static_assert(sizeof(struct v4l2_jpegcompression) ==
	       _IOC_SIZE(VIDIOC_G_JPEGCOMP),
	       "v4l2_jpegcompression size vs VIDIOC_G_JPEGCOMP mismatch");
_Static_assert(sizeof(struct v4l2_jpegcompression) ==
	       _IOC_SIZE(VIDIOC_S_JPEGCOMP),
	       "v4l2_jpegcompression size vs VIDIOC_S_JPEGCOMP mismatch");
_Static_assert(sizeof(struct v4l2_audio) ==
	       _IOC_SIZE(VIDIOC_ENUMAUDIO),
	       "v4l2_audio size vs VIDIOC_ENUMAUDIO mismatch");
_Static_assert(sizeof(struct v4l2_audioout) ==
	       _IOC_SIZE(VIDIOC_ENUMAUDOUT),
	       "v4l2_audioout size vs VIDIOC_ENUMAUDOUT mismatch");
_Static_assert(sizeof(struct v4l2_sliced_vbi_cap) ==
	       _IOC_SIZE(VIDIOC_G_SLICED_VBI_CAP),
	       "v4l2_sliced_vbi_cap size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_ext_controls) ==
	       _IOC_SIZE(VIDIOC_G_EXT_CTRLS),
	       "v4l2_ext_controls size vs VIDIOC_G_EXT_CTRLS mismatch");
_Static_assert(sizeof(struct v4l2_ext_controls) ==
	       _IOC_SIZE(VIDIOC_S_EXT_CTRLS),
	       "v4l2_ext_controls size vs VIDIOC_S_EXT_CTRLS mismatch");
_Static_assert(sizeof(struct v4l2_ext_controls) ==
	       _IOC_SIZE(VIDIOC_TRY_EXT_CTRLS),
	       "v4l2_ext_controls size vs VIDIOC_TRY_EXT_CTRLS mismatch");
_Static_assert(sizeof(struct v4l2_frmsizeenum) ==
	       _IOC_SIZE(VIDIOC_ENUM_FRAMESIZES),
	       "v4l2_frmsizeenum size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_frmivalenum) ==
	       _IOC_SIZE(VIDIOC_ENUM_FRAMEINTERVALS),
	       "v4l2_frmivalenum size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_enc_idx) ==
	       _IOC_SIZE(VIDIOC_G_ENC_INDEX),
	       "v4l2_enc_idx size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct v4l2_encoder_cmd) ==
	       _IOC_SIZE(VIDIOC_ENCODER_CMD),
	       "v4l2_encoder_cmd size vs VIDIOC_ENCODER_CMD mismatch");
_Static_assert(sizeof(struct v4l2_encoder_cmd) ==
	       _IOC_SIZE(VIDIOC_TRY_ENCODER_CMD),
	       "v4l2_encoder_cmd size vs VIDIOC_TRY_ENCODER_CMD mismatch");
_Static_assert(sizeof(struct v4l2_dbg_register) ==
	       _IOC_SIZE(VIDIOC_DBG_S_REGISTER),
	       "v4l2_dbg_register size vs VIDIOC_DBG_S_REGISTER mismatch");
_Static_assert(sizeof(struct v4l2_dbg_register) ==
	       _IOC_SIZE(VIDIOC_DBG_G_REGISTER),
	       "v4l2_dbg_register size vs VIDIOC_DBG_G_REGISTER mismatch");
_Static_assert(sizeof(struct v4l2_hw_freq_seek) ==
	       _IOC_SIZE(VIDIOC_S_HW_FREQ_SEEK),
	       "v4l2_hw_freq_seek size vs _IOC_SIZE mismatch");
#ifdef VIDIOC_S_DV_TIMINGS
_Static_assert(sizeof(struct v4l2_dv_timings) ==
	       _IOC_SIZE(VIDIOC_S_DV_TIMINGS),
	       "v4l2_dv_timings size vs VIDIOC_S_DV_TIMINGS mismatch");
#endif
#ifdef VIDIOC_G_DV_TIMINGS
_Static_assert(sizeof(struct v4l2_dv_timings) ==
	       _IOC_SIZE(VIDIOC_G_DV_TIMINGS),
	       "v4l2_dv_timings size vs VIDIOC_G_DV_TIMINGS mismatch");
#endif
#ifdef VIDIOC_DQEVENT
_Static_assert(sizeof(struct v4l2_event) ==
	       _IOC_SIZE(VIDIOC_DQEVENT),
	       "v4l2_event size vs _IOC_SIZE mismatch");
#endif
#ifdef VIDIOC_SUBSCRIBE_EVENT
_Static_assert(sizeof(struct v4l2_event_subscription) ==
	       _IOC_SIZE(VIDIOC_SUBSCRIBE_EVENT),
	       "v4l2_event_subscription size vs VIDIOC_SUBSCRIBE_EVENT mismatch");
#endif
#ifdef VIDIOC_UNSUBSCRIBE_EVENT
_Static_assert(sizeof(struct v4l2_event_subscription) ==
	       _IOC_SIZE(VIDIOC_UNSUBSCRIBE_EVENT),
	       "v4l2_event_subscription size vs VIDIOC_UNSUBSCRIBE_EVENT mismatch");
#endif
#ifdef VIDIOC_CREATE_BUFS
_Static_assert(sizeof(struct v4l2_create_buffers) ==
	       _IOC_SIZE(VIDIOC_CREATE_BUFS),
	       "v4l2_create_buffers size vs _IOC_SIZE mismatch");
#endif
#ifdef VIDIOC_PREPARE_BUF
_Static_assert(sizeof(struct v4l2_buffer) ==
	       _IOC_SIZE(VIDIOC_PREPARE_BUF),
	       "v4l2_buffer size vs VIDIOC_PREPARE_BUF mismatch");
#endif
#ifdef VIDIOC_G_SELECTION
_Static_assert(sizeof(struct v4l2_selection) ==
	       _IOC_SIZE(VIDIOC_G_SELECTION),
	       "v4l2_selection size vs VIDIOC_G_SELECTION mismatch");
#endif
#ifdef VIDIOC_S_SELECTION
_Static_assert(sizeof(struct v4l2_selection) ==
	       _IOC_SIZE(VIDIOC_S_SELECTION),
	       "v4l2_selection size vs VIDIOC_S_SELECTION mismatch");
#endif
#ifdef VIDIOC_DECODER_CMD
_Static_assert(sizeof(struct v4l2_decoder_cmd) ==
	       _IOC_SIZE(VIDIOC_DECODER_CMD),
	       "v4l2_decoder_cmd size vs VIDIOC_DECODER_CMD mismatch");
#endif
#ifdef VIDIOC_TRY_DECODER_CMD
_Static_assert(sizeof(struct v4l2_decoder_cmd) ==
	       _IOC_SIZE(VIDIOC_TRY_DECODER_CMD),
	       "v4l2_decoder_cmd size vs VIDIOC_TRY_DECODER_CMD mismatch");
#endif
#ifdef VIDIOC_ENUM_DV_TIMINGS
_Static_assert(sizeof(struct v4l2_enum_dv_timings) ==
	       _IOC_SIZE(VIDIOC_ENUM_DV_TIMINGS),
	       "v4l2_enum_dv_timings size vs _IOC_SIZE mismatch");
#endif
#ifdef VIDIOC_QUERY_DV_TIMINGS
_Static_assert(sizeof(struct v4l2_dv_timings) ==
	       _IOC_SIZE(VIDIOC_QUERY_DV_TIMINGS),
	       "v4l2_dv_timings size vs VIDIOC_QUERY_DV_TIMINGS mismatch");
#endif
#ifdef VIDIOC_DV_TIMINGS_CAP
_Static_assert(sizeof(struct v4l2_dv_timings_cap) ==
	       _IOC_SIZE(VIDIOC_DV_TIMINGS_CAP),
	       "v4l2_dv_timings_cap size vs _IOC_SIZE mismatch");
#endif
#ifdef VIDIOC_ENUM_FREQ_BANDS
_Static_assert(sizeof(struct v4l2_frequency_band) ==
	       _IOC_SIZE(VIDIOC_ENUM_FREQ_BANDS),
	       "v4l2_frequency_band size vs _IOC_SIZE mismatch");
#endif

static const struct ioctl videodev2_ioctls[] = {
	IOCTL(VIDIOC_QUERYCAP),
#ifdef VIDIOC_RESERVED
	IOCTL(VIDIOC_RESERVED),
#endif
	IOCTL(VIDIOC_ENUM_FMT),
	IOCTL(VIDIOC_G_FMT),
	IOCTL(VIDIOC_S_FMT),
	IOCTL(VIDIOC_REQBUFS),
	IOCTL(VIDIOC_QUERYBUF),
	IOCTL(VIDIOC_G_FBUF),
	IOCTL(VIDIOC_S_FBUF),
	IOCTL(VIDIOC_OVERLAY),
	IOCTL(VIDIOC_QBUF),
#ifdef VIDIOC_EXPBUF
	IOCTL(VIDIOC_EXPBUF),
#endif
	IOCTL(VIDIOC_DQBUF),
	IOCTL(VIDIOC_STREAMON),
	IOCTL(VIDIOC_STREAMOFF),
	IOCTL(VIDIOC_G_PARM),
	IOCTL(VIDIOC_S_PARM),
	IOCTL(VIDIOC_G_STD),
	IOCTL(VIDIOC_S_STD),
	IOCTL(VIDIOC_ENUMSTD),
	IOCTL(VIDIOC_ENUMINPUT),
	IOCTL(VIDIOC_G_CTRL),
	IOCTL(VIDIOC_S_CTRL),
	IOCTL(VIDIOC_G_TUNER),
	IOCTL(VIDIOC_S_TUNER),
	IOCTL(VIDIOC_G_AUDIO),
	IOCTL(VIDIOC_S_AUDIO),
	IOCTL(VIDIOC_QUERYCTRL),
	IOCTL(VIDIOC_QUERYMENU),
	IOCTL(VIDIOC_G_INPUT),
	IOCTL(VIDIOC_S_INPUT),
	IOCTL(VIDIOC_G_OUTPUT),
	IOCTL(VIDIOC_S_OUTPUT),
	IOCTL(VIDIOC_ENUMOUTPUT),
	IOCTL(VIDIOC_G_AUDOUT),
	IOCTL(VIDIOC_S_AUDOUT),
	IOCTL(VIDIOC_G_MODULATOR),
	IOCTL(VIDIOC_S_MODULATOR),
	IOCTL(VIDIOC_G_FREQUENCY),
	IOCTL(VIDIOC_S_FREQUENCY),
	IOCTL(VIDIOC_CROPCAP),
	IOCTL(VIDIOC_G_CROP),
	IOCTL(VIDIOC_S_CROP),
	IOCTL(VIDIOC_G_JPEGCOMP),
	IOCTL(VIDIOC_S_JPEGCOMP),
	IOCTL(VIDIOC_QUERYSTD),
	IOCTL(VIDIOC_TRY_FMT),
	IOCTL(VIDIOC_ENUMAUDIO),
	IOCTL(VIDIOC_ENUMAUDOUT),
	IOCTL(VIDIOC_G_PRIORITY),
	IOCTL(VIDIOC_S_PRIORITY),
	IOCTL(VIDIOC_G_SLICED_VBI_CAP),
	IOCTL(VIDIOC_LOG_STATUS),
	IOCTL(VIDIOC_G_EXT_CTRLS),
	IOCTL(VIDIOC_S_EXT_CTRLS),
	IOCTL(VIDIOC_TRY_EXT_CTRLS),
	IOCTL(VIDIOC_ENUM_FRAMESIZES),
	IOCTL(VIDIOC_ENUM_FRAMEINTERVALS),
	IOCTL(VIDIOC_G_ENC_INDEX),
	IOCTL(VIDIOC_ENCODER_CMD),
	IOCTL(VIDIOC_TRY_ENCODER_CMD),
	IOCTL(VIDIOC_DBG_S_REGISTER),
	IOCTL(VIDIOC_DBG_G_REGISTER),
#ifdef VIDIOC_DBG_G_CHIP_IDENT
	IOCTL(VIDIOC_DBG_G_CHIP_IDENT),
#endif
	IOCTL(VIDIOC_S_HW_FREQ_SEEK),
#ifdef VIDIOC_ENUM_DV_PRESETS
	IOCTL(VIDIOC_ENUM_DV_PRESETS),
#endif
#ifdef VIDIOC_S_DV_PRESET
	IOCTL(VIDIOC_S_DV_PRESET),
#endif
#ifdef VIDIOC_G_DV_PRESET
	IOCTL(VIDIOC_G_DV_PRESET),
#endif
#ifdef VIDIOC_QUERY_DV_PRESET
	IOCTL(VIDIOC_QUERY_DV_PRESET),
#endif
#ifdef VIDIOC_S_DV_TIMINGS
	IOCTL(VIDIOC_S_DV_TIMINGS),
#endif
#ifdef VIDIOC_G_DV_TIMINGS
	IOCTL(VIDIOC_G_DV_TIMINGS),
#endif
#ifdef VIDIOC_DQEVENT
	IOCTL(VIDIOC_DQEVENT),
#endif
#ifdef VIDIOC_SUBSCRIBE_EVENT
	IOCTL(VIDIOC_SUBSCRIBE_EVENT),
#endif
#ifdef VIDIOC_UNSUBSCRIBE_EVENT
	IOCTL(VIDIOC_UNSUBSCRIBE_EVENT),
#endif
#ifdef VIDIOC_CREATE_BUFS
	IOCTL(VIDIOC_CREATE_BUFS),
#endif
#ifdef VIDIOC_PREPARE_BUF
	IOCTL(VIDIOC_PREPARE_BUF),
#endif
#ifdef VIDIOC_G_SELECTION
	IOCTL(VIDIOC_G_SELECTION),
#endif
#ifdef VIDIOC_S_SELECTION
	IOCTL(VIDIOC_S_SELECTION),
#endif
#ifdef VIDIOC_DECODER_CMD
	IOCTL(VIDIOC_DECODER_CMD),
#endif
#ifdef VIDIOC_TRY_DECODER_CMD
	IOCTL(VIDIOC_TRY_DECODER_CMD),
#endif
#ifdef VIDIOC_ENUM_DV_TIMINGS
	IOCTL(VIDIOC_ENUM_DV_TIMINGS),
#endif
#ifdef VIDIOC_QUERY_DV_TIMINGS
	IOCTL(VIDIOC_QUERY_DV_TIMINGS),
#endif
#ifdef VIDIOC_DV_TIMINGS_CAP
	IOCTL(VIDIOC_DV_TIMINGS_CAP),
#endif
#ifdef VIDIOC_ENUM_FREQ_BANDS
	IOCTL(VIDIOC_ENUM_FREQ_BANDS),
#endif
};

static const char *const videodev2_devs[] = {
	"video4linux",
};

static const struct ioctl_group videodev2_grp = {
	.devtype = DEV_MISC,
	.devs = videodev2_devs,
	.devs_cnt = ARRAY_SIZE(videodev2_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = videodev2_ioctls,
	.ioctls_cnt = ARRAY_SIZE(videodev2_ioctls),
};

REG_IOCTL_GROUP(videodev2_grp)
