/* SHA-512 Digest Wrapper Implementation using leancrypto.
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * This program and the accompanying materials are licensed and made available
 * under the terms and conditions of the BSD License which accompanies this
 * distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php
 */

#include "InternalCryptLib.h"

/* define strlen to ensure its definition is not taken from leancrypto */
#define strlen
#include <leancrypto.h>

/**
 * Retrieves the size, in bytes, of the context buffer required for SHA-512
 * hash operations.
 *
 * @return The size, in bytes, of the context buffer required for SHA-512 hash
 *	   operations.
 */
UINTN EFIAPI Sha512GetContextSize(VOID)
{
	/*
	 * Retrieves leancrypto SHA-512 Context Size
	 *
	 * Add the memory for proper alignment in the calls below
	 */
	return (UINTN)(LC_SHA512_CTX_SIZE + LC_HASH_COMMON_ALIGNMENT);
}

/**
 * Initializes user-supplied memory pointed by Sha512Context as SHA-512 hash
 * context for subsequent use.
 *
 * If Sha512Context is NULL, then return FALSE.
 *
 * @param[out] Sha512Context  Pointer to SHA-512 context being initialized.
 *
 * @retval TRUE SHA-512 context initialization succeeded.
 * @retval FALSE SHA-512 context initialization failed.
 */
BOOLEAN EFIAPI Sha512Init (OUT VOID *Sha512Context)
{
	struct lc_hash_ctx *ctx;

	/* Check input parameters. */
	if (Sha512Context == NULL) {
		return FALSE;
	}

	ctx = (struct lc_hash_ctx *)LC_ALIGN_PTR_64(Sha512Context,
						    LC_HASH_COMMON_ALIGNMENT);

	/* leancrypto SHA-512 Context Initialization */
	LC_SHA512_CTX(ctx);
	lc_hash_init(ctx);

	return TRUE;
}

/**
 * Makes a copy of an existing SHA-512 context.
 *
 * If Sha512Context is NULL, then return FALSE.
 * If NewSha512Context is NULL, then return FALSE.
 *
 * @param[in] Sha512Context Pointer to SHA-512 context being copied.
 * @param[out] NewSha512Context Pointer to new SHA-512 context.
 *
 * @retval TRUE SHA-512 context copy succeeded.
 * @retval FALSE SHA-512 context copy failed.
 */
BOOLEAN EFIAPI Sha512Duplicate (IN CONST VOID *Sha512Context,
				OUT VOID *NewSha512Context)
{
	/* Check input parameters. */
	if (Sha512Context == NULL || NewSha512Context == NULL) {
		return FALSE;
	}

	CopyMem(NewSha512Context, (void *)Sha512Context,
		LC_SHA512_CTX_SIZE + LC_HASH_COMMON_ALIGNMENT);

	return TRUE;
}

/**
 * Digests the input data and updates SHA-512 context.
 *
 * This function performs SHA-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or
 * discontinuous data streams. SHA-512 context should be already correctly
 * initialized by Sha512Init(), and should not be finalized
 * by Sha512Final(). Behavior with invalid context is undefined.
 *
 * If Sha512Context is NULL, then return FALSE.
 *
 * @param[in,out] Sha512Context Pointer to the SHA-512 context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 *
 * @retval TRUE SHA-512 data digest succeeded.
 * @retval FALSE SHA-512 data digest failed.
 */
BOOLEAN EFIAPI Sha512Update (IN OUT VOID *Sha512Context,IN CONST VOID *Data,
			     IN UINTN DataSize)
{
	struct lc_hash_ctx *ctx;

	/* Check input parameters. */
	if (Sha512Context == NULL) {
		return FALSE;
	}

	ctx = (struct lc_hash_ctx *)LC_ALIGN_PTR_64(Sha512Context,
						    LC_HASH_COMMON_ALIGNMENT);

	/* leancrypto SHA-512 Hash Update */
	lc_hash_update(ctx, Data, DataSize);

	return TRUE;
}

/**
 * Completes computation of the SHA-512 digest value.
 *
 * This function completes SHA-512 hash computation and retrieves the digest
 * value into the specified memory. After this function has been called, the
 * SHA-512 context cannot be used again. SHA-512 context should be already
 * correctly initialized by Sha512Init(), and should not be finalized by
 * Sha512Final(). Behavior with invalid SHA-512 context is undefined.
 *
 * If Sha512Context is NULL, then return FALSE.
 * If HashValue is NULL, then return FALSE.
 *
 * @param[in,out] Sha512Context Pointer to the SHA-512 context.
 * @param[out] HashValue Pointer to a buffer that receives the SHA-512 digest
 *			 value (32 bytes).
 *
 * @retval TRUE SHA-512 digest computation succeeded.
 * @retval FALSE SHA-512 digest computation failed.
 */
BOOLEAN EFIAPI Sha512Final (IN OUT VOID *Sha512Context, OUT UINT8 *HashValue)
{
	struct lc_hash_ctx *ctx;

	/* Check input parameters. */
	if (Sha512Context == NULL || HashValue == NULL) {
		return FALSE;
	}

	ctx = (struct lc_hash_ctx *)LC_ALIGN_PTR_64(Sha512Context,
						    LC_HASH_COMMON_ALIGNMENT);

	/* leancrypto SHA-512 Hash Finalization */
	lc_hash_final(ctx, HashValue);

	return TRUE;
}

/**
 * Computes the SHA-512 message digest of a input data buffer.
 *
 * This function performs the SHA-512 message digest of a given data buffer, and
 * places the digest value into the specified memory.
 *
 * If this interface is not supported, then return FALSE.
 *
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashValue Pointer to a buffer that receives the SHA-512 digest
 *			 value (32 bytes).
 *
 * @retval TRUE SHA-512 digest computation succeeded.
 * @retval FALSE SHA-512 digest computation failed.
 */
BOOLEAN EFIAPI Sha512HashAll (IN CONST VOID *Data, IN UINTN DataSize,
			      OUT UINT8 *HashValue)
{
	/* Check input parameters. */
	if (HashValue == NULL) {
		return FALSE;
	}

	/* leancrypto SHA-512 Hash Computation. */
	lc_hash(lc_sha512, Data, DataSize, HashValue);

	return TRUE;
}
