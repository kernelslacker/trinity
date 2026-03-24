#pragma once

/* From linux/tls.h */
struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

/* TLS versions */
#define TLS_VERSION_MINOR(ver)  ((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)  (((ver) >> 8) & 0xFF)
#define TLS_VERSION_NUMBER(id)  ((((id##_VERSION_MAJOR) & 0xFF) << 8) | \
                                 ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR   0x3
#define TLS_1_2_VERSION_MINOR   0x3
#define TLS_1_2_VERSION         TLS_VERSION_NUMBER(TLS_1_2)

#define TLS_1_3_VERSION_MAJOR   0x3
#define TLS_1_3_VERSION_MINOR   0x4
#define TLS_1_3_VERSION         TLS_VERSION_NUMBER(TLS_1_3)

/* TLS setsockopt optnames */
#define TLS_TX                  1
#define TLS_RX                  2
#define TLS_TX_ZEROCOPY_RO      3
#define TLS_RX_EXPECT_NO_PAD    4

/* Cipher types */
#define TLS_CIPHER_AES_GCM_128                  51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE          8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE         16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE        4
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE     8

#define TLS_CIPHER_AES_GCM_256                  52
#define TLS_CIPHER_AES_GCM_256_IV_SIZE          8
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE         32
#define TLS_CIPHER_AES_GCM_256_SALT_SIZE        4
#define TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE     8

#define TLS_CIPHER_AES_CCM_128                  53
#define TLS_CIPHER_AES_CCM_128_IV_SIZE          8
#define TLS_CIPHER_AES_CCM_128_KEY_SIZE         16
#define TLS_CIPHER_AES_CCM_128_SALT_SIZE        4
#define TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE     8

#define TLS_CIPHER_CHACHA20_POLY1305            54
#define TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE    12
#define TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE   32
#define TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE  0
#define TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE 8

#define TLS_CIPHER_SM4_GCM                      55
#define TLS_CIPHER_SM4_GCM_IV_SIZE              8
#define TLS_CIPHER_SM4_GCM_KEY_SIZE             16
#define TLS_CIPHER_SM4_GCM_SALT_SIZE            4
#define TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE         8

#define TLS_CIPHER_SM4_CCM                      56
#define TLS_CIPHER_SM4_CCM_IV_SIZE              8
#define TLS_CIPHER_SM4_CCM_KEY_SIZE             16
#define TLS_CIPHER_SM4_CCM_SALT_SIZE            4
#define TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE         8

/* Per-cipher crypto_info structs */
struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

struct tls12_crypto_info_aes_gcm_256 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_256_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE];
};

struct tls12_crypto_info_aes_ccm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_CCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_CCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_CCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE];
};

struct tls12_crypto_info_chacha20_poly1305 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE];
	unsigned char key[TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE];
	/* no salt — CHACHA20_POLY1305 salt size is 0 */
	unsigned char rec_seq[TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE];
};

struct tls12_crypto_info_sm4_gcm {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_SM4_GCM_IV_SIZE];
	unsigned char key[TLS_CIPHER_SM4_GCM_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_SM4_GCM_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE];
};

struct tls12_crypto_info_sm4_ccm {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_SM4_CCM_IV_SIZE];
	unsigned char key[TLS_CIPHER_SM4_CCM_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_SM4_CCM_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE];
};
