/*
 * setsockopt-internal.h
 *
 * Shared declarations split out of syscalls/setsockopt.c so the
 * per-(level, optname) optval builders (build_int_*, build_linger,
 * build_timeval, build_ip_mreqn, build_ipv6_mreq, build_packet_mreq,
 * the build_sctp_* family, build_string_ifname) can live in their
 * own translation unit and compile in parallel with the dispatch
 * table, paired-sockopt engine and syscall hooks.  This header is
 * private to the two TUs that make up setsockopt -- do not include it
 * from anywhere else.
 *
 * The builders touch no file-statics in setsockopt.c; they read only
 * trinity's rnd_* RNG helpers and write a sized payload into the
 * caller-owned buffer.  Each is deliberately widened from file-static
 * to external linkage so the sockopt_table[] / sockopt_pairs[]
 * dispatch tables in setsockopt.c can reference them across the TU
 * boundary.
 */

#ifndef SYSCALLS_SETSOCKOPT_INTERNAL_H
#define SYSCALLS_SETSOCKOPT_INTERNAL_H

#include <sys/socket.h>
#include "config.h"

socklen_t build_int_bool(void *buf);
socklen_t build_int_rand(void *buf);
socklen_t build_int_small_positive(void *buf);
socklen_t build_linger(void *buf);
socklen_t build_timeval(void *buf);
socklen_t build_ip_mreqn(void *buf);
socklen_t build_ipv6_mreq(void *buf);
socklen_t build_packet_mreq(void *buf);

#ifdef USE_SCTP
socklen_t build_sctp_initmsg(void *buf);
socklen_t build_sctp_rtoinfo(void *buf);
socklen_t build_sctp_assocparams(void *buf);
socklen_t build_sctp_setadaptation(void *buf);
socklen_t build_sctp_assoc_value(void *buf);
socklen_t build_sctp_sndinfo(void *buf);
socklen_t build_sctp_sndrcvinfo(void *buf);
socklen_t build_sctp_events(void *buf);
socklen_t build_sctp_authchunk(void *buf);
socklen_t build_sctp_sackinfo(void *buf);
socklen_t build_sctp_authkeyid(void *buf);
socklen_t build_sctp_default_prinfo(void *buf);
socklen_t build_sctp_add_streams(void *buf);
socklen_t build_sctp_stream_value(void *buf);
socklen_t build_sctp_event(void *buf);
socklen_t build_sctp_paddrthlds(void *buf);
socklen_t build_sctp_paddrthlds_v2(void *buf);
socklen_t build_sctp_udpencaps(void *buf);
socklen_t build_sctp_paddrparams(void *buf);
socklen_t build_sctp_probeinterval(void *buf);
socklen_t build_sctp_prim(void *buf);
#endif

socklen_t build_string_ifname(void *buf);

#endif /* SYSCALLS_SETSOCKOPT_INTERNAL_H */
