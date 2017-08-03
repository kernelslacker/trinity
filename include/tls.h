#pragma once

/* From linux/tls.h */
struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

#define TLS_CIPHER_AES_GCM_128_IV_SIZE 8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE 16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE 4
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8

#define TLS_VERSION_MINOR(ver)  ((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)  (((ver) >> 8) & 0xFF)
#define TLS_VERSION_NUMBER(id)  ((((id##_VERSION_MAJOR) & 0xFF) << 8) | \
                                 ((id##_VERSION_MINOR) & 0xFF))
#define TLS_1_2_VERSION_MAJOR   0x3
#define TLS_1_2_VERSION_MINOR   0x3
#define TLS_1_2_VERSION         TLS_VERSION_NUMBER(TLS_1_2)

#define TLS_CIPHER_AES_GCM_128 51

#define TLS_TX 1

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};
