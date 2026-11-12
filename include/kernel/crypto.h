#pragma once

/* include/linux/crypto.h: the one flag alg_bind() takes in salg_feat and
 * salg_mask. */
#ifndef CRYPTO_ALG_KERN_DRIVER_ONLY
#define CRYPTO_ALG_KERN_DRIVER_ONLY	0x00001000
#endif
