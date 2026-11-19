#pragma once

/* include/linux/crypto.h: the one flag alg_bind() takes in salg_feat and
 * salg_mask. */
#ifndef CRYPTO_ALG_KERN_DRIVER_ONLY
#define CRYPTO_ALG_KERN_DRIVER_ONLY	0x00001000
#endif

/* include/crypto/authenc.h: the rtattr type of the key blob
 * crypto_authenc_extractkeys() and crypto_krb5enc_extractkeys() parse. */
#ifndef CRYPTO_AUTHENC_KEYA_PARAM
#define CRYPTO_AUTHENC_KEYA_PARAM	1
#endif
