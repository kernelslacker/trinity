/*
 * cmsg-richness lever — gates the extended sendmsg/sendmmsg cmsg
 * coverage on the arg-gen path.
 *
 * Default OFF: pick_cmsg_kind() keeps drawing from the original five
 * base kinds via a single rnd_modulo_u32 call, so the RNG stream is
 * byte-identical to a build without this lever.  ON adds family-gated
 * extra single-cmsg kinds and a multi-cmsg packer behind extra RNG
 * draws that fire only when the mode is flipped on.
 */
#ifndef _TRINITY_CMSG_RICHNESS_H
#define _TRINITY_CMSG_RICHNESS_H

enum cmsg_richness_mode {
	CMSG_RICHNESS_OFF = 0,
	CMSG_RICHNESS_ON = 1,
};

extern enum cmsg_richness_mode cmsg_richness_mode;

#endif /* _TRINITY_CMSG_RICHNESS_H */
