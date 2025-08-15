// SPDX-License-Identifier: BSD-2-Clause-Patent

#include "shim.h"

#include <Library/BaseCryptLib.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#define strlen
#include <leancrypto.h>

#define TRAD_DES_HASH_SIZE 13 /* (64/6+1) + (12/6) */
#define BSDI_DES_HASH_SIZE 20 /* (64/6+1) + (24/6) + 4 + 1 */
#define BLOWFISH_HASH_SIZE 31 /* 184/6+1 */
#include <Library/BaseCryptLib.h>

UINT16 get_hash_size (const UINT16 method)
{
	switch (method) {
	case TRADITIONAL_DES:
		return TRAD_DES_HASH_SIZE;
	case EXTEND_BSDI_DES:
		return BSDI_DES_HASH_SIZE;
	case MD5_BASED:
		return MD5_DIGEST_LENGTH;
	case SHA256_BASED:
		return LC_SHA256_SIZE_DIGEST;
	case SHA512_BASED:
		return LC_SHA512_SIZE_DIGEST;
	case BLOWFISH_BASED:
		return BLOWFISH_HASH_SIZE;
	default:
		return 0;
	}

	return 0;
}

static const char md5_salt_prefix[] = "$1$";

static EFI_STATUS md5_crypt (const char *key,  UINT32 key_len,
			     const char *salt, UINT32 salt_size,
			     UINT8 *hash)
{
	MD5_CTX ctx, alt_ctx;
	UINT8 alt_result[MD5_DIGEST_LENGTH];
	UINTN cnt;

	MD5_Init(&ctx);
	MD5_Update(&ctx, key, key_len);
	MD5_Update(&ctx, md5_salt_prefix, sizeof(md5_salt_prefix) - 1);
	MD5_Update(&ctx, salt, salt_size);

	MD5_Init(&alt_ctx);
	MD5_Update(&alt_ctx, key, key_len);
	MD5_Update(&alt_ctx, salt, salt_size);
	MD5_Update(&alt_ctx, key, key_len);
	MD5_Final(alt_result, &alt_ctx);

	for (cnt = key_len; cnt > 16; cnt -= 16)
		MD5_Update(&ctx, alt_result, 16);
	MD5_Update(&ctx, alt_result, cnt);

	*alt_result = '\0';

	for (cnt = key_len; cnt > 0; cnt >>= 1) {
		if ((cnt & 1) != 0) {
			MD5_Update(&ctx, alt_result, 1);
		} else {
			MD5_Update(&ctx, key, 1);
		}
	}
	MD5_Final(alt_result, &ctx);

	for (cnt = 0; cnt < 1000; ++cnt) {
		MD5_Init(&ctx);

		if ((cnt & 1) != 0)
			MD5_Update(&ctx, key, key_len);
		else
			MD5_Update(&ctx, alt_result, 16);

		if (cnt % 3 != 0)
			MD5_Update(&ctx, salt, salt_size);

		if (cnt % 7 != 0)
			MD5_Update(&ctx, key, key_len);

		if ((cnt & 1) != 0)
			MD5_Update(&ctx, alt_result, 16);
		else
			MD5_Update(&ctx, key, key_len);

		MD5_Final(alt_result, &ctx);
	}

	CopyMem(hash, alt_result, MD5_DIGEST_LENGTH);

	return EFI_SUCCESS;
}

static EFI_STATUS hash_crypt (struct lc_hash_ctx *ctx,
			      struct lc_hash_ctx *alt_ctx, UINT8 digestsize,
			      const UINT8 *key,  UINT32 key_len,
			      const UINT8 *salt, UINT32 salt_size,
			      const UINT32 rounds, UINT8 *hash)
{
	UINT8 alt_result[LC_SHA_MAX_SIZE_DIGEST];
	UINT8 tmp_result[LC_SHA_MAX_SIZE_DIGEST];
	UINT8 *cp, *p_bytes = NULL, *s_bytes = NULL;
	UINTN cnt;
	EFI_STATUS ret = EFI_SUCCESS;

	lc_hash_init(ctx);
	lc_hash_update(ctx, key, key_len);
	lc_hash_update(ctx, salt, salt_size);

	lc_hash_init(alt_ctx);
	lc_hash_update(alt_ctx, key, key_len);
	lc_hash_update(alt_ctx, salt, salt_size);
	lc_hash_update(alt_ctx, key, key_len);
	lc_hash_final(alt_ctx, alt_result);

	for (cnt = key_len; cnt > digestsize; cnt -= digestsize)
		lc_hash_update(ctx, alt_result, digestsize);
	lc_hash_update(ctx, alt_result, cnt);

	for (cnt = key_len; cnt > 0; cnt >>= 1) {
		if ((cnt & 1) != 0) {
			lc_hash_update(ctx, alt_result, digestsize);
		} else {
			lc_hash_update(ctx, key, key_len);
		}
	}
	lc_hash_final(ctx, alt_result);

	lc_hash_init(alt_ctx);
	for (cnt = 0; cnt < key_len; ++cnt)
		lc_hash_update(alt_ctx, key, key_len);
	lc_hash_final(alt_ctx, tmp_result);

	cp = p_bytes = AllocatePool(key_len);
	if (!p_bytes) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	for (cnt = key_len; cnt >= digestsize; cnt -= digestsize) {
		CopyMem(cp, tmp_result, digestsize);
		cp += digestsize;
	}
	CopyMem(cp, tmp_result, cnt);

	lc_hash_init(alt_ctx);
	for (cnt = 0; cnt < 16ul + alt_result[0]; ++cnt)
		lc_hash_update(alt_ctx, salt, salt_size);
	lc_hash_final(alt_ctx, tmp_result);

	cp = s_bytes = AllocatePool(salt_size);
	if (!s_bytes) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	for (cnt = salt_size; cnt >= digestsize; cnt -= digestsize) {
		CopyMem(cp, tmp_result, digestsize);
		cp += digestsize;
	}
	CopyMem(cp, tmp_result, cnt);

	for (cnt = 0; cnt < rounds; ++cnt) {
		lc_hash_init(ctx);

		if ((cnt & 1) != 0)
			lc_hash_update(ctx, p_bytes, key_len);
		else
			lc_hash_update(ctx, alt_result, digestsize);

		if (cnt % 3 != 0)
			lc_hash_update(ctx, s_bytes, salt_size);

		if (cnt % 7 != 0)
			lc_hash_update(ctx, p_bytes, key_len);

		if ((cnt & 1) != 0)
			lc_hash_update(ctx, alt_result, digestsize);
		else
			lc_hash_update(ctx, p_bytes, key_len);

		lc_hash_final(ctx, alt_result);
	}

	CopyMem(hash, alt_result, digestsize);

out:
	if (p_bytes)
		FreePool(p_bytes);
	if (s_bytes)
		FreePool(s_bytes);

	lc_memset_secure(alt_result, 0, digestsize);
	lc_memset_secure(tmp_result, 0, digestsize);

	return ret;
}

static EFI_STATUS sha256_crypt (const char *key,  UINT32 key_len,
				const char *salt, UINT32 salt_size,
				const UINT32 rounds, UINT8 *hash)
{
	EFI_STATUS ret;
	LC_SHA256_CTX_ON_STACK(ctx);
	LC_SHA256_CTX_ON_STACK(alt_ctx);

	ret = hash_crypt (ctx, alt_ctx, LC_SHA256_SIZE_DIGEST, (UINT8 *)key,
			  key_len, (UINT8 *)salt, salt_size, rounds, hash);

	lc_hash_zero(ctx);
	lc_hash_zero(alt_ctx);

	return ret;
}

static EFI_STATUS sha512_crypt (const char *key,  UINT32 key_len,
				const char *salt, UINT32 salt_size,
				const UINT32 rounds, UINT8 *hash)
{
	EFI_STATUS ret;
	LC_SHA512_CTX_ON_STACK(ctx);
	LC_SHA512_CTX_ON_STACK(alt_ctx);

	ret = hash_crypt (ctx, alt_ctx, LC_SHA512_SIZE_DIGEST, (UINT8 *)key,
			  key_len, (UINT8 *)salt, salt_size, rounds, hash);

	lc_hash_zero(ctx);
	lc_hash_zero(alt_ctx);

	return ret;
}

#define BF_RESULT_SIZE (7 + 22 + 31 + 1)

static EFI_STATUS blowfish_crypt (const char *key, const char *salt, UINT8 *hash)
{
	char *retval, result[BF_RESULT_SIZE];

	retval = crypt_blowfish_rn (key, salt, result, BF_RESULT_SIZE);
	if (!retval)
		return EFI_UNSUPPORTED;

	CopyMem(hash, result + 7 + 22, BF_RESULT_SIZE);

	return EFI_SUCCESS;
}

EFI_STATUS password_crypt (const char *password, UINT32 pw_length,
			   const PASSWORD_CRYPT *pw_crypt, UINT8 *hash)
{
	EFI_STATUS efi_status;

	if (!pw_crypt)
		return EFI_INVALID_PARAMETER;

	switch (pw_crypt->method) {
	case TRADITIONAL_DES:
	case EXTEND_BSDI_DES:
		efi_status = EFI_UNSUPPORTED;
		break;
	case MD5_BASED:
		efi_status = md5_crypt (password, pw_length,
					(char *)pw_crypt->salt,
					pw_crypt->salt_size, hash);
		break;
	case SHA256_BASED:
		efi_status = sha256_crypt(password, pw_length,
					  (char *)pw_crypt->salt,
					  pw_crypt->salt_size,
					  pw_crypt->iter_count, hash);
		break;
	case SHA512_BASED:
		efi_status = sha512_crypt(password, pw_length,
					  (char *)pw_crypt->salt,
					  pw_crypt->salt_size,
					  pw_crypt->iter_count, hash);
		break;
	case BLOWFISH_BASED:
		if (pw_crypt->salt_size != (7 + 22 + 1)) {
			efi_status = EFI_INVALID_PARAMETER;
			break;
		}
		efi_status = blowfish_crypt(password, (char *)pw_crypt->salt,
					    hash);
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

	return efi_status;
}
