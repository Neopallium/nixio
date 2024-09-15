/*
 * nixio - Linux I/O library for lua
 *
 *   Copyright (C) 2009 Steven Barth <steven@midlink.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "nixio-tls.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef WITHOUT_OPENSSL
int impl_hash_create(lua_State *L, nixio_hash *hash, const char *name) {
  const EVP_MD* md = NULL;

	hash->type = NIXIO_HASH_EVP;
	if (!strcmp(name, "md5")) {
    md = EVP_md5();
	} else if (!strcmp(name, "sha1")) {
    md = EVP_sha1();
	} else {
    md = EVP_get_digestbyname(name);
  }
  if (md == NULL) {
    return luaL_error(L, "Unsupported OpenSSL EVP digest: %s", name);
	}

  EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

  if(!EVP_DigestInit_ex(mdctx, md, NULL)) {
    return luaL_error(L, "EVP_DigestInit_ex failed.");
  }
	hash->digest_size = EVP_MD_size(md);
	hash->block_size = EVP_MD_block_size(md);
  hash->ctx = mdctx;

	return 1;
}

int impl_hash_init(lua_State *L, nixio_hash *hash) {
  if (hash->ctx == NULL) {
    return luaL_error(L, "EVP_MD_CTX has been destroyed.");
  }
  EVP_MD_CTX* mdctx = hash->ctx;
  const EVP_MD* md = EVP_MD_CTX_get0_md(mdctx);
  if (md == NULL) {
    return luaL_error(L, "EVP_MD_CTX has no EVP_MD type.");
  }
  if(!EVP_DigestInit_ex(mdctx, md, NULL)) {
    return luaL_error(L, "EVP_DigestInit_ex failed.");
  }
	return 1;
}

int impl_hash_update(lua_State *L, nixio_hash *hash, const void *buf, size_t count) {
  if (hash->ctx == NULL) {
    return luaL_error(L, "EVP_MD_CTX has been destroyed.");
  }
  EVP_MD_CTX* mdctx = hash->ctx;
  if(!EVP_DigestUpdate(mdctx, buf, count)) {
    return luaL_error(L, "EVP_DigestUpdate failed.");
  }

	return 1;
}

int impl_hash_final(lua_State *L, nixio_hash *hash) {
  if (hash->ctx == NULL) {
    return luaL_error(L, "EVP_MD_CTX has been destroyed.");
  }
  unsigned int md_len = 0;
  EVP_MD_CTX* mdctx = hash->ctx;
  if(!EVP_DigestFinal_ex(mdctx, hash->digest, &md_len)) {
    return luaL_error(L, "EVP_DigestFinal_ex failed.");
  }

	return 1;
}

int impl_hash_destroy(lua_State *L, nixio_hash *hash) {
	hash->type = NIXIO_HASH_NONE;
  if (hash->ctx != NULL) {
    EVP_MD_CTX_destroy(hash->ctx);
    hash->ctx = NULL;
  }
	return 1;
}
#else
int impl_hash_create(lua_State *L, nixio_hash *hash, const char *name) {
	if (!strcmp(name, "md5")) {
		hash->type = NIXIO_HASH_MD5;
		hash->digest_size = MD5_DIGEST_LENGTH;
		hash->block_size = 64;
		hash->ctx = malloc(sizeof(MD5_CTX));
		if (!hash->ctx) {
			return luaL_error(L, NIXIO_OOM);
		}
		MD5_Init((MD5_CTX*)hash->ctx);
	} else if (!strcmp(name, "sha1")) {
		hash->type = NIXIO_HASH_SHA1;
		hash->digest_size = SHA_DIGEST_LENGTH;
		hash->block_size = 64;
		hash->ctx = malloc(sizeof(SHA_CTX));
		if (!hash->ctx) {
			return luaL_error(L, NIXIO_OOM);
		}
		SHA1_Init((SHA_CTX*)hash->ctx);
	} else {
		luaL_argerror(L, 1, "supported values: md5, sha1");
	}

	return 1;
}

int impl_hash_init(lua_State *L, nixio_hash *hash) {
  if ((hash->type & NIXIO_HASH_MD5) != 0) {
    MD5_Init((MD5_CTX*)hash->ctx);
  } else if ((hash->type & NIXIO_HASH_SHA1) != 0) {
    SHA1_Init((SHA_CTX*)hash->ctx);
  }
	return 1;
}

int impl_hash_update(lua_State *L, nixio_hash *hash, const void *buf, size_t count) {
  if ((hash->type & NIXIO_HASH_MD5) != 0) {
    MD5_Update((MD5_CTX*)hash->ctx, buf, count);
  } else if ((hash->type & NIXIO_HASH_SHA1) != 0) {
    SHA1_Update((SHA_CTX*)hash->ctx, buf, count);
  }
	return 1;
}

int impl_hash_final(lua_State *L, nixio_hash *hash) {
  if ((hash->type & NIXIO_HASH_MD5) != 0) {
    MD5_Final(hash->digest, (MD5_CTX*)hash->ctx);
  } else if ((hash->type & NIXIO_HASH_SHA1) != 0) {
    SHA1_Final(hash->digest, (SHA_CTX*)hash->ctx);
  }
	return 1;
}

int impl_hash_destroy(lua_State *L, nixio_hash *hash) {
	hash->type = NIXIO_HASH_NONE;
  if (hash->ctx != NULL) {
	  free(hash->ctx);
    hash->ctx = NULL;
  }
	return 1;
}
#endif

static int nixio_crypto_hash__init(lua_State *L, int hmac) {
	const char *type = luaL_checkstring(L, 1);
	nixio_hash *hash = lua_newuserdata(L, sizeof(nixio_hash));

  impl_hash_create(L, hash, type);

	luaL_getmetatable(L, NIXIO_CRYPTO_HASH_META);
	lua_setmetatable(L, -2);

	if (hmac) {
		const char *key = luaL_checklstring(L, 2, &hash->key_size);
		if (hash->key_size > hash->block_size) {
      impl_hash_update(L, hash, key, hash->key_size);
      impl_hash_final(L, hash);
      impl_hash_init(L, hash);
			hash->key_size = hash->digest_size;
			memcpy(hash->key, hash->digest, hash->key_size);
		} else {
			memcpy(hash->key, key, hash->key_size);
		}

		unsigned char pad[NIXIO_CRYPTO_BLOCK_SIZE];
		for (uint i = 0; i < hash->block_size; i++) {
			pad[i] = (i < hash->key_size) ? (0x36 ^ hash->key[i]) : 0x36;
		}
    impl_hash_update(L, hash, pad, hash->block_size);
		hash->type |= NIXIO_HMAC_BIT;
	}

	return 1;
}

static int nixio_crypto_hash(lua_State *L) {
	return nixio_crypto_hash__init(L, 0);
}

static int nixio_crypto_hmac(lua_State *L) {
	return nixio_crypto_hash__init(L, 1);
}

static int nixio_crypto_hash_reinit(lua_State *L) {
	nixio_hash *hash = luaL_checkudata(L, 1, NIXIO_CRYPTO_HASH_META);
  impl_hash_init(L, hash);
  hash->type &= ~NIXIO_FINAL_BIT;

	return 1;
}

static int nixio_crypto_hash_update(lua_State *L) {
	nixio_hash *hash = luaL_checkudata(L, 1, NIXIO_CRYPTO_HASH_META);
	if (hash->type) {
		size_t len;
		const char *chunk = luaL_checklstring(L, 2, &len);
    impl_hash_update(L, hash, chunk, len);
		lua_pushvalue(L, 1);
		return 1;
	} else {
		return luaL_error(L, "Tried to update finalized hash object.");
	}
}

static int nixio_crypto_hash_final(lua_State *L) {
	nixio_hash *hash = luaL_checkudata(L, 1, NIXIO_CRYPTO_HASH_META);
	if (hash->type & NIXIO_HMAC_BIT) {
    impl_hash_final(L, hash);
    impl_hash_init(L, hash);

		unsigned char pad[NIXIO_CRYPTO_BLOCK_SIZE];
		for (uint i = 0; i < hash->block_size; i++) {
			pad[i] = (i < hash->key_size) ? (0x5c ^ hash->key[i]) : 0x5c;
		}

    impl_hash_update(L, hash, pad, hash->block_size);
    impl_hash_update(L, hash, hash->digest, hash->digest_size);
  }
	if (!(hash->type & NIXIO_FINAL_BIT)) {
    hash->type |= NIXIO_FINAL_BIT;
    impl_hash_final(L, hash);
  }

	char hashdigest[NIXIO_DIGEST_SIZE*2];
	for (uint i=0; i < hash->digest_size; i++) {
		hashdigest[2*i]   = nixio__bin2hex[(hash->digest[i] & 0xf0) >> 4];
		hashdigest[2*i+1] = nixio__bin2hex[(hash->digest[i] & 0x0f)];
	}

	lua_pushlstring(L, hashdigest, hash->digest_size * 2);
	memcpy(hashdigest, hash->digest, hash->digest_size);
	lua_pushlstring(L, hashdigest, hash->digest_size);

	return 2;
}

static int nixio_crypto_hash__gc(lua_State *L) {
	nixio_hash *hash = luaL_checkudata(L, 1, NIXIO_CRYPTO_HASH_META);
  impl_hash_destroy(L, hash);
	return 0;
}

static int nixio_crypto_hash__tostring(lua_State *L) {
	nixio_hash *hash = luaL_checkudata(L, 1, NIXIO_CRYPTO_HASH_META);
	lua_pushfstring(L, "nixio hash object: %p", hash);
	return 1;
}


/* module table */
static const luaL_Reg R[] = {
	{"hash",		nixio_crypto_hash},
	{"hmac",		nixio_crypto_hmac},
	{NULL,			NULL}
};

/* hash table */
static const luaL_Reg M[] = {
	{"reinit",		nixio_crypto_hash_reinit},
	{"update",		nixio_crypto_hash_update},
	{"final",		nixio_crypto_hash_final},
	{"__gc",		nixio_crypto_hash__gc},
	{"__tostring",	nixio_crypto_hash__tostring},
	{NULL,			NULL}
};



void nixio_open_tls_crypto(lua_State *L) {
	luaL_newmetatable(L, NIXIO_CRYPTO_HASH_META);
	luaL_register(L, NULL, M);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	lua_newtable(L);
    luaL_register(L, NULL, R);

	lua_setfield(L, -2, "crypto");
}
