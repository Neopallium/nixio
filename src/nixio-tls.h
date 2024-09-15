#ifndef NIXIO_TLS_H_
#define NIXIO_TLS_H_

#include "nixio.h"
#include <sys/types.h>

#ifndef WITHOUT_OPENSSL
#include <openssl/ssl.h>
#endif

#define NIXIO_TLS_CTX_META "nixio.tls.ctx"
#define NIXIO_TLS_SOCK_META "nixio.tls.sock"

typedef struct nixio_tls_socket {
	SSL		*socket;
#ifdef WITH_AXTLS
	char	connected;
	size_t	pbufsiz;
	char	*pbufpos;
	char	*pbuffer;
#endif
} nixio_tls_sock;

#define NIXIO_CRYPTO_HASH_META "nixio.crypto.hash"
#define NIXIO_DIGEST_SIZE 64
#define NIXIO_CRYPTO_BLOCK_SIZE 64

#define NIXIO_HASH_NONE	0
#define NIXIO_HASH_MD5	0x01
#define NIXIO_HASH_SHA1	0x02
#define NIXIO_HASH_EVP	0x04

#define NIXIO_HMAC_BIT	0x40
#define NIXIO_FINAL_BIT	0x80

typedef struct nixio_hash_obj {
	uint				type;
	unsigned char		digest[NIXIO_DIGEST_SIZE];
	size_t				digest_size;
	unsigned char		key[NIXIO_CRYPTO_BLOCK_SIZE];
	size_t				key_size;
	size_t				block_size;
	void				*ctx;
} nixio_hash;

#endif /* NIXIO_TLS_H_ */
