/* Pseudorandom Number Generator Wrapper Implementation using leancrypto.
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * This program and the accompanying materials are licensed and made available
 * under the terms and conditions of the BSD License which accompanies this
 * distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php
 */

#include "InternalCryptLib.h"
#define strlen
#include <leancrypto.h>

/* Default seed for UEFI Crypto Library */
CONST UINT8  DefaultSeed[] = "UEFI Crypto Library default seed";

/**
 * Sets up the seed value for the pseudorandom number generator.
 *
 * This function sets up the seed value for the pseudorandom number generator.
 * As the leancrypto random number generator is always properly seeded, any
 * input data is used as additional information only.
 *
 * @param[in] Seed Pointer to seed value. If NULL, default seed is used.
 * @param[in] SeedSize Size of seed value. If Seed is NULL, this parameter is
 *		       ignored.
 *
 * @retval TRUE Pseudorandom number generator has enough entropy for random
 *		generation.
 * @retval FALSE Pseudorandom number generator does not have enough entropy for
 *		 random generation.
 */
BOOLEAN EFIAPI RandomSeed (IN CONST UINT8 *Seed  OPTIONAL, IN UINTN SeedSize)
{
	int ret;

	if (SeedSize > INT_MAX)
		return FALSE;

	if (Seed != NULL) {
		ret = lc_rng_seed(lc_seeded_rng, Seed, SeedSize, NULL, 0);
	} else {
		ret = lc_rng_seed(lc_seeded_rng, DefaultSeed,
				  sizeof(DefaultSeed), NULL, 0);
	}

	if (ret < 0)
		return FALSE;

	return TRUE;
}

/**
 * Generates a pseudorandom byte stream of the specified size.
 *
 * If Output is NULL, then return FALSE.
 *
 * @param[out] Output Pointer to buffer to receive random value.
 * @param[in] Size Size of random bytes to generate.
 *
 * @retval TRUE Pseudorandom byte stream generated successfully.
 * @retval FALSE Pseudorandom number generator fails to generate due to lack of
 *		 entropy.
 */
BOOLEAN EFIAPI RandomBytes (OUT UINT8 *Output, IN UINTN Size)
{
	/* Check input parameters. */
	if (Output == NULL || Size > INT_MAX)
		return FALSE;

	/* Generate random data. */
	if (lc_rng_generate(lc_seeded_rng, NULL, 0,  Output, Size))
		return FALSE;

	return TRUE;
}
