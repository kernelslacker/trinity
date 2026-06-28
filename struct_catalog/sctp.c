/*
 * struct_catalog/sctp.c -- SCTP setsockopt optval struct field tables.
 *
 * Carved out of struct_catalog.c as the first leaf TU of an incremental
 * file split: the central spine (struct_catalog[],
 * syscall_struct_args[]) and all logic stay in struct_catalog.c; this
 * TU owns the SCTP leaf data only.  Symbols are declared extern (with
 * explicit array sizes so ARRAY_SIZE() at the spine resolves) in
 * struct_catalog-internal.h, which the spine includes so its
 * designated initialisers ([SC_SCTP_*] = ... .fields = sctp_*_fields)
 * keep linking.
 *
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty when USE_SCTP is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_SCTP
/*
 * <sys/socket.h> declares MSG_FIN and the sockaddr_storage type that
 * <linux/sctp.h>'s SCTP_EOF / sockaddr_storage-bearing structs name in
 * their definitions; it has to land first so those references resolve.
 */
#include <sys/socket.h>
#include <linux/sctp.h>

#include "utils.h"

/*
 * struct sctp_initmsg -- IPPROTO_SCTP / SCTP_INITMSG.  Four __u16 fields
 * controlling SCTP association init params.  Stream counts bound to
 * [0, 128] (the kernel caps max_instreams/num_ostreams well below this in
 * practice), max_attempts bounded to a sane small INIT retry count, and
 * max_init_timeo bounded to a millisecond window matching the SCTP RTO
 * envelope.  Bespoke build_sctp_initmsg() zero-fills as a miss-fallback;
 * the schema fill above produces values inside the kernel's accept
 * window.  Schema-aware FILL only -- no field-scoped CMP attribution
 * for setsockopt optval (see section header).
 */
const struct struct_field sctp_initmsg_fields[SCTP_INITMSG_FIELDS_N] = {
	FIELDX(struct sctp_initmsg, sinit_num_ostreams, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_initmsg, sinit_max_instreams, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_initmsg, sinit_max_attempts, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 40),
	FIELDX(struct sctp_initmsg, sinit_max_init_timeo, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 40),
};

/*
 * struct sctp_rtoinfo -- IPPROTO_SCTP / SCTP_RTOINFO.  Carries the SCTP
 * RTO (retransmission timeout) envelope for an association: assoc_id
 * picks the target association (FT_RAW lets the per-byte splat drive
 * the kernel's per-assoc lookup) and three __u32 millisecond fields
 * (initial / max / min) bounded to [0, 60000] -- a window wide enough to
 * exercise the kernel's clamp logic without flooding it with absurd
 * values.  Bespoke build_sctp_rtoinfo() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_rtoinfo_fields[SCTP_RTOINFO_FIELDS_N] = {
	FIELDX(struct sctp_rtoinfo, srto_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_initial, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_max, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_min, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_assocparams -- IPPROTO_SCTP / SCTP_ASSOCINFO.  Examines
 * and sets various per-association and endpoint parameters.  sasoc_assoc_id
 * picks the target association (FT_RAW so the per-field splat continues to
 * drive the association lookup).  sasoc_asocmaxrxt is the association-level
 * max retransmit (FT_RANGE [0, 16] keeps it within plausible retry budgets).
 * sasoc_number_peer_destinations / sasoc_peer_rwnd / sasoc_local_rwnd
 * are FT_RAW (peer-count and window-byte counters with no useful clamp).
 * sasoc_cookie_life is the cookie lifetime in milliseconds, FT_RANGE
 * [0, 60000] to exercise the kernel's clamp without flooding the input
 * validator.  Bespoke build_sctp_assocparams() zero-fills as a
 * miss-fallback.
 */
const struct struct_field sctp_assocparams_fields[SCTP_ASSOCPARAMS_FIELDS_N] = {
	FIELDX(struct sctp_assocparams, sasoc_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_assocparams, sasoc_asocmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_assocparams, sasoc_number_peer_destinations, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_peer_rwnd, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_local_rwnd, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_cookie_life, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_setadaptation -- IPPROTO_SCTP / SCTP_ADAPTATION_LAYER.
 * RFC 5061 / RFC 5062 indication value advertised to the peer at
 * association setup; the kernel stores it verbatim and echoes it back
 * in the ADAPTATION-INDICATION parameter.  Single member
 * ssb_adaptation_ind (__u32) is FT_RAW -- arbitrary peer-visible
 * cookie with no useful clamp.  Bespoke build_sctp_setadaptation()
 * zero-fills as a miss-fallback.
 */
const struct struct_field sctp_setadaptation_fields[SCTP_SETADAPTATION_FIELDS_N] = {
	FIELDX(struct sctp_setadaptation, ssb_adaptation_ind, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_assoc_value -- IPPROTO_SCTP / { SCTP_CONTEXT, SCTP_MAXSEG,
 * SCTP_MAX_BURST, SCTP_STREAM_SCHEDULER }.  Two-field carrier shared by
 * several sockopts that take an (assoc_id, value) pair: assoc_id picks
 * the target association (FT_RAW so the per-field splat continues to
 * drive the association lookup), assoc_value is the per-optname payload
 * (FT_RAW -- value semantics differ per optname: SCTP_CONTEXT is an
 * opaque cookie, SCTP_MAXSEG / SCTP_MAX_BURST / SCTP_STREAM_SCHEDULER
 * are small integers with kernel-side clamping, so a single FT_RANGE
 * wouldn't fit all four).
 * Bespoke build_sctp_assoc_value() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_assoc_value_fields[SCTP_ASSOC_VALUE_FIELDS_N] = {
	FIELDX(struct sctp_assoc_value, assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_assoc_value, assoc_value, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sndinfo -- IPPROTO_SCTP / SCTP_DEFAULT_SNDINFO.  RFC 6458
 * default per-stream send parameters: snd_sid picks the target stream
 * (FT_RANGE [0, 128] matches the SCTP_INITMSG stream-count envelope and
 * keeps the value inside the kernel's accept window).  snd_flags is a
 * bitfield drawn from the SCTP send-flag set (UNORDERED / ADDR_OVER /
 * ABORT / SACK_IMMEDIATELY / SENDALL / EOF), masked so the splat lands
 * on plausible combinations rather than random 16-bit noise.  snd_ppid
 * (peer-visible payload protocol id), snd_context (opaque per-message
 * cookie), and snd_assoc_id (association lookup key) are FT_RAW -- each
 * is either peer-visible / opaque or a lookup constant the kernel
 * compares against.  Bespoke build_sctp_sndinfo() zero-fills as a
 * miss-fallback.
 */
const struct struct_field sctp_sndinfo_fields[SCTP_SNDINFO_FIELDS_N] = {
	FIELDX(struct sctp_sndinfo, snd_sid, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndinfo, snd_flags, FT_FLAGS,
	       .u.flags.mask = (SCTP_UNORDERED | SCTP_ADDR_OVER |
				SCTP_ABORT | SCTP_SACK_IMMEDIATELY |
				SCTP_SENDALL | SCTP_EOF),
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndinfo, snd_ppid, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndinfo, snd_context, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndinfo, snd_assoc_id, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sndrcvinfo -- IPPROTO_SCTP / SCTP_DEFAULT_SEND_PARAM.  The
 * legacy default-send-parameters struct (RFC 6458's older sndrcvinfo);
 * sinfo_stream picks the target stream (FT_RANGE [0, 128] matches the
 * SCTP_INITMSG stream-count envelope and keeps the value inside the
 * kernel's accept window).  sinfo_flags is a bitfield drawn from the
 * SCTP send-flag set (UNORDERED / ADDR_OVER / ABORT / SACK_IMMEDIATELY
 * / SENDALL / EOF), masked so the splat lands on plausible combinations
 * rather than random 16-bit noise.  sinfo_ssn / sinfo_ppid /
 * sinfo_context / sinfo_timetolive / sinfo_tsn / sinfo_cumtsn /
 * sinfo_assoc_id are FT_RAW -- each is either peer-visible / opaque or
 * a lookup constant the kernel compares against.  Bespoke
 * build_sctp_sndrcvinfo() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_sndrcvinfo_fields[SCTP_SNDRCVINFO_FIELDS_N] = {
	FIELDX(struct sctp_sndrcvinfo, sinfo_stream, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndrcvinfo, sinfo_ssn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_flags, FT_FLAGS,
	       .u.flags.mask = (SCTP_UNORDERED | SCTP_ADDR_OVER |
				SCTP_ABORT | SCTP_SACK_IMMEDIATELY |
				SCTP_SENDALL | SCTP_EOF),
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndrcvinfo, sinfo_ppid, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_context, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_timetolive, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_tsn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_cumtsn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_assoc_id, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_event_subscribe -- IPPROTO_SCTP / SCTP_EVENTS.  Legacy
 * notification-subscription bitmap (RFC 6458's older event-subscribe
 * predecessor to SCTP_EVENT) consisting of one __u8 boolean per
 * notification type.  Each field is FT_RANGE [0, 1] so the per-field
 * splat lands on the in-spec 0/1 values rather than random byte noise;
 * the kernel's setsockopt parser tolerates any non-zero byte as "on",
 * but staying inside [0, 1] keeps the request realistic.  Bespoke
 * build_sctp_events() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_event_subscribe_fields[SCTP_EVENT_SUBSCRIBE_FIELDS_N] = {
	FIELDX(struct sctp_event_subscribe, sctp_data_io_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_association_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_address_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_send_failure_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_peer_error_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_shutdown_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_partial_delivery_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_adaptation_layer_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_authentication_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_sender_dry_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_stream_reset_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_assoc_reset_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_stream_change_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_send_failure_event_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
};

/*
 * struct sctp_authchunk -- IPPROTO_SCTP / SCTP_AUTH_CHUNK.  RFC 4895
 * AUTH extension: register a chunk type whose receipt the local
 * endpoint requires to be carried inside an AUTH chunk.  Single
 * member sauth_chunk (__u8) is FT_RAW -- arbitrary chunk-type id; the
 * kernel validates against its own chunk-type table at sockopt time
 * and ignores anything it does not recognise, so no useful clamp.
 * Bespoke build_sctp_authchunk() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_authchunk_fields[SCTP_AUTHCHUNK_FIELDS_N] = {
	FIELDX(struct sctp_authchunk, sauth_chunk, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sack_info -- IPPROTO_SCTP / SCTP_DELAYED_SACK (the canonical
 * spelling; SCTP_DELAYED_ACK / SCTP_DELAYED_ACK_TIME alias the same
 * optname value 16).  RFC 6458 delayed-SACK tuning: sack_assoc_id picks
 * the target association (FT_RAW so the kernel's per-assoc lookup
 * constant shows up to KCOV-CMP), sack_delay is the delayed-ack timer
 * in ms bounded to [0, 500] -- the kernel rejects values above
 * SCTP_MAX_DELAY_VALUE (500ms) outright, so staying inside the window
 * exercises the timer-arm path rather than the EINVAL early-out, and
 * sack_freq is the every-Nth-packet ack frequency bounded to [0, 16]
 * which keeps the kernel's freq counter inside a realistic envelope
 * without flooding the SACK-immediate path.  Bespoke build_sctp_sackinfo()
 * zero-fills as a miss-fallback.
 */
const struct struct_field sctp_sack_info_fields[SCTP_SACK_INFO_FIELDS_N] = {
	FIELDX(struct sctp_sack_info, sack_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_sack_info, sack_delay, FT_RANGE,
	       .u.range = { 0, 500 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sack_info, sack_freq, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_authkeyid -- IPPROTO_SCTP / SCTP_AUTH_{ACTIVE,DELETE,
 * DEACTIVATE}_KEY.  RFC 4895 AUTH key management: scact_assoc_id picks
 * the target association (FT_RAW so the kernel's per-assoc lookup
 * constant shows up to KCOV-CMP), scact_keynumber is the shared-key
 * identifier bounded to [0, 8] -- realistic for the small set of keys an
 * endpoint typically provisions while still exercising the lookup path.
 * Bespoke build_sctp_authkeyid() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_authkeyid_fields[SCTP_AUTHKEYID_FIELDS_N] = {
	FIELDX(struct sctp_authkeyid, scact_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_authkeyid, scact_keynumber, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_default_prinfo -- IPPROTO_SCTP / SCTP_DEFAULT_PRINFO.
 * RFC 7496 PR-SCTP default policy carrier: pr_assoc_id selects the
 * target association (FT_RAW so the per-assoc lookup constant shows
 * up to KCOV-CMP), pr_value is the policy-specific lifetime / retx
 * limit / priority cookie (FT_RAW -- semantics differ per policy and
 * the kernel does not clamp), and pr_policy is the small 4-valued
 * vocab the kernel branches on in sctp_set_default_prinfo() (FT_ENUM
 * over SCTP_PR_SCTP_{NONE,TTL,RTX,PRIO} keeps the mutator inside the
 * legal shape -- any other value is rejected with -EINVAL).  Bespoke
 * build_sctp_default_prinfo() zero-fills as a miss-fallback.
 */
const unsigned long sctp_default_prinfo_policy_values[SCTP_DEFAULT_PRINFO_POLICY_VALUES_N] = {
	SCTP_PR_SCTP_NONE, SCTP_PR_SCTP_TTL,
	SCTP_PR_SCTP_RTX,  SCTP_PR_SCTP_PRIO,
};

const struct struct_field sctp_default_prinfo_fields[SCTP_DEFAULT_PRINFO_FIELDS_N] = {
	FIELDX(struct sctp_default_prinfo, pr_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_default_prinfo, pr_value, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_default_prinfo, pr_policy, FT_ENUM,
	       .u.enum_ = { sctp_default_prinfo_policy_values,
			    ARRAY_SIZE(sctp_default_prinfo_policy_values) },
	       .mutate_weight = 80),
};

/*
 * struct sctp_add_streams -- IPPROTO_SCTP / SCTP_ADD_STREAMS.  RFC 6525
 * dynamic stream reconfiguration: sas_assoc_id picks the target
 * association (FT_RAW so the kernel's per-assoc lookup constant shows
 * up to KCOV-CMP) while sas_instrms / sas_outstrms request how many
 * additional inbound / outbound streams to negotiate, bounded to
 * [0, 128] -- the kernel branches on (current + requested) overflowing
 * 16 bits and on the peer's RECONF capability, so staying inside a
 * realistic envelope exercises the negotiation path rather than the
 * EINVAL early-out.  Bespoke build_sctp_add_streams() zero-fills as a
 * miss-fallback.
 */
const struct struct_field sctp_add_streams_fields[SCTP_ADD_STREAMS_FIELDS_N] = {
	FIELDX(struct sctp_add_streams, sas_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_add_streams, sas_instrms, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_add_streams, sas_outstrms, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_stream_value -- IPPROTO_SCTP / SCTP_STREAM_SCHEDULER_VALUE.
 * Per-stream scheduler parameter carrier: assoc_id selects the
 * association (FT_RAW so the kernel's per-assoc lookup constant shows
 * up to KCOV-CMP), stream_id picks the target stream bounded to
 * [0, 128] matching the SCTP_INITMSG stream-count envelope, and
 * stream_value is the scheduler-specific opaque cookie (FT_RAW; the
 * kernel's interpretation varies by active scheduler so no useful
 * clamp).  Bespoke build_sctp_stream_value() zero-fills as a
 * miss-fallback.
 */
const struct struct_field sctp_stream_value_fields[SCTP_STREAM_VALUE_FIELDS_N] = {
	FIELDX(struct sctp_stream_value, assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_stream_value, stream_id, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_stream_value, stream_value, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_event -- IPPROTO_SCTP / SCTP_EVENT.  RFC 6458 generic
 * notification-subscription opt (the modern per-event toggle that
 * superseded the legacy SCTP_EVENTS / sctp_event_subscribe bitmap):
 * se_assoc_id selects the target association (FT_RAW so the kernel's
 * per-assoc lookup constant shows up to KCOV-CMP), se_type names the
 * sctp_sn_type notification (FT_RAW -- the value list lives in the
 * SCTP_SN_TYPE_BASE = (1<<15) range rather than a contiguous small
 * enum, so the byte-noise default still hits the live span often
 * enough), and se_on is the on/off toggle clamped to [0, 1] so the
 * splat lands on the in-spec boolean rather than random noise.
 * Bespoke build_sctp_event() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_event_fields[SCTP_EVENT_FIELDS_N] = {
	FIELDX(struct sctp_event, se_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_event, se_type, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_event, se_on, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 50),
};

/*
 * struct sctp_paddrthlds -- IPPROTO_SCTP / SCTP_PEER_ADDR_THLDS.  Per-
 * peer-address retransmit / partial-failure threshold opt (RFC 5062 +
 * the peer-failure draft).  spt_assoc_id picks the target association
 * (FT_RAW so the per-assoc lookup constant shows up to KCOV-CMP);
 * spt_address embeds a struct sockaddr_storage and is treated as a
 * single opaque FT_RAW blob spanning sizeof(struct sockaddr_storage)
 * -- the kernel matches it against the live peer address list rather
 * than parsing it field-wise, so the per-byte splat is the right
 * shape and field-splitting it would just give KCOV-CMP misleading
 * sub-field offsets for a value that is logically atomic.
 * spt_pathmaxrxt is the per-path max retransmit (__u16, FT_RANGE
 * [0, 16] -- keeps it inside plausible retry budgets) and
 * spt_pathpfthld is the partial-failure threshold (__u16, FT_RANGE
 * [0, 16] -- same envelope).  Bespoke build_sctp_paddrthlds()
 * zero-fills as a miss-fallback.
 */
const struct struct_field sctp_paddrthlds_fields[SCTP_PADDRTHLDS_FIELDS_N] = {
	FIELDX(struct sctp_paddrthlds, spt_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds, spt_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrthlds, spt_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds, spt_pathpfthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_paddrthlds_v2 -- IPPROTO_SCTP / SCTP_PEER_ADDR_THLDS_V2.
 * Back-compat extension of struct sctp_paddrthlds adding a trailing
 * spt_pathcpthld (__u16, FT_RANGE [0, 16]) -- the per-path
 * consecutive-retransmit threshold the v2 optname carries on top of
 * the v1 layout.  Everything else mirrors v1: spt_assoc_id is FT_RAW
 * so the per-assoc lookup constant shows up to KCOV-CMP, spt_address
 * is a single opaque FT_RAW blob spanning sizeof(struct
 * sockaddr_storage), and spt_pathmaxrxt / spt_pathpfthld stay in the
 * [0, 16] envelope.  Bespoke build_sctp_paddrthlds_v2() zero-fills
 * as a miss-fallback.
 */
const struct struct_field sctp_paddrthlds_v2_fields[SCTP_PADDRTHLDS_V2_FIELDS_N] = {
	FIELDX(struct sctp_paddrthlds_v2, spt_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathpfthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathcpthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_udpencaps -- IPPROTO_SCTP / SCTP_REMOTE_UDP_ENCAPS_PORT.
 * Per-peer UDP encapsulation port for SCTP-over-UDP (RFC 6951).
 * sue_assoc_id picks the target association (sctp_assoc_t / __u32,
 * FT_RAW so the per-assoc lookup constant shows up to KCOV-CMP).
 * sue_address embeds a struct sockaddr_storage and is treated as a
 * single opaque FT_RAW blob spanning sizeof(struct sockaddr_storage)
 * -- the kernel matches it against the live peer address list rather
 * than parsing it field-wise, so the per-byte splat is the right
 * shape and field-splitting it would just give KCOV-CMP misleading
 * sub-field offsets for a value that is logically atomic.  sue_port
 * is the UDP encapsulation port (__u16, network/big-endian; FT_RAW
 * to let the per-byte splat exercise both bytes without anchoring
 * KCOV-CMP at a single canonical value).  Bespoke
 * build_sctp_udpencaps() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_udpencaps_fields[SCTP_UDPENCAPS_FIELDS_N] = {
	FIELDX(struct sctp_udpencaps, sue_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_udpencaps, sue_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_udpencaps, sue_port, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_paddrparams -- IPPROTO_SCTP / SCTP_PEER_ADDR_PARAMS.
 * Per-peer-address heartbeat / PMTU / SACK-delay parameter block
 * (RFC 6458 7.1.13).  spp_assoc_id picks the target association
 * (sctp_assoc_t / __u32, FT_RAW so the per-assoc lookup constant
 * shows up to KCOV-CMP); spp_address embeds a struct sockaddr_storage
 * and is treated as a single opaque FT_RAW blob spanning
 * sizeof(struct sockaddr_storage) -- the kernel matches it against
 * the live peer address list rather than parsing it field-wise, so
 * the per-byte splat is the right shape and field-splitting it would
 * just give KCOV-CMP misleading sub-field offsets for a value that
 * is logically atomic.  spp_hbinterval / spp_pathmtu / spp_sackdelay
 * are __u32 timer/MTU/delay knobs (FT_RAW -- letting the per-byte
 * splat exercise the full range without anchoring KCOV-CMP at a
 * single canonical value); spp_pathmaxrxt is __u16, FT_RANGE
 * [0, 16] -- keeps it inside plausible retry budgets matching the
 * paddrthlds rows.  spp_flags is the SPP_* bitset and is masked to
 * the documented bit set (SPP_HB_{ENABLE,DISABLE,DEMAND},
 * SPP_PMTUD_{ENABLE,DISABLE}, SPP_SACKDELAY_{ENABLE,DISABLE},
 * SPP_HB_TIME_IS_ZERO, SPP_IPV6_FLOWLABEL, SPP_DSCP).
 * spp_ipv6_flowlabel (__u32) and spp_dscp (__u8) are RAW.  The
 * struct is packed,aligned(4) -- compiler-derived offsetof() in
 * FIELDX honors the packing.  Bespoke build_sctp_paddrparams()
 * zero-fills as a miss-fallback.
 */
const struct struct_field sctp_paddrparams_fields[SCTP_PADDRPARAMS_FIELDS_N] = {
	FIELDX(struct sctp_paddrparams, spp_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrparams, spp_hbinterval, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_pathmtu, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_sackdelay, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_flags, FT_FLAGS,
	       .u.flags.mask = SPP_HB_ENABLE | SPP_HB_DISABLE |
			       SPP_HB_DEMAND |
			       SPP_PMTUD_ENABLE | SPP_PMTUD_DISABLE |
			       SPP_SACKDELAY_ENABLE | SPP_SACKDELAY_DISABLE |
			       SPP_HB_TIME_IS_ZERO |
			       SPP_IPV6_FLOWLABEL | SPP_DSCP,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_ipv6_flowlabel, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrparams, spp_dscp, FT_RAW,
	       .mutate_weight = 40),
};

/*
 * struct sctp_probeinterval -- IPPROTO_SCTP / SCTP_PLPMTUD_PROBE_INTERVAL.
 * PLPMTUD (Packetization Layer Path MTU Discovery, RFC 8899) probe-interval
 * knob exposed by SCTP.  spi_assoc_id (sctp_assoc_t / __u32) picks the
 * target association -- FT_RAW so the per-assoc lookup constant shows up
 * to KCOV-CMP.  spi_address embeds a struct sockaddr_storage and is
 * treated as a single opaque FT_RAW blob; the kernel matches it against
 * the live peer address list rather than parsing it field-wise, so the
 * per-byte splat is the right shape and field-splitting it would just
 * give KCOV-CMP misleading sub-field offsets for a value that is
 * logically atomic.  spi_interval is the probe interval in milliseconds
 * (__u32, unsigned) -- FT_RANGE [0, 60000] keeps the splat inside the
 * documented kernel envelope (0 disables, otherwise plausible PMTUD
 * cadence) rather than scattering across the full u32 space.  Bespoke
 * build_sctp_probeinterval() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_probeinterval_fields[SCTP_PROBEINTERVAL_FIELDS_N] = {
	FIELDX(struct sctp_probeinterval, spi_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_probeinterval, spi_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_probeinterval, spi_interval, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_prim -- IPPROTO_SCTP / { SCTP_PRIMARY_ADDR,
 * SCTP_SET_PEER_PRIMARY_ADDR }.  Two setsockopt names share one
 * payload shape: a struct sctp_prim (also spelled sctp_setprim) made
 * of an sctp_assoc_t association selector and a sockaddr_storage
 * naming the peer address to promote.  The struct is declared
 * __attribute__((packed, aligned(4))), so ssp_addr sits at offset 4
 * with no trailing padding; FIELD()/FIELDX() pick up that layout via
 * offsetof, no manual offset arithmetic required.  ssp_assoc_id
 * (FT_RAW) lets the per-assoc lookup constant flow to KCOV-CMP.
 * ssp_addr is opaque to the kernel's address-match path (it's
 * compared against the live peer list rather than parsed field-wise),
 * so a single FT_RAW splat over the whole sockaddr_storage is the
 * right granularity; field-splitting it would only give KCOV-CMP
 * misleading sub-field offsets for a value the kernel treats as
 * atomic.  Bespoke build_sctp_prim() zero-fills as a miss-fallback.
 */
const struct struct_field sctp_prim_fields[SCTP_PRIM_FIELDS_N] = {
	FIELDX(struct sctp_prim, ssp_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_prim, ssp_addr, FT_RAW,
	       .mutate_weight = 40),
};
#endif /* USE_SCTP */
