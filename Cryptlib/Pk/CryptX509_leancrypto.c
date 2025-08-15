/* X.509 Certificate Handler Wrapper Implementation using leancrypto.
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
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If Cert is NULL, then return FALSE.
 * If SingleX509Cert is NULL, then return FALSE.
 *
 * @param[in] Cert Pointer to the DER-encoded certificate data.
 * @param[in] CertSize The size of certificate data in bytes.
 * @param[out] SingleX509Cert The generated X509 object.
 *
 * @retval TRUE The X509 object generation succeeded.
 * @retval FALSE The operation failed.
 */
BOOLEAN EFIAPI X509ConstructCertificate (IN CONST UINT8 *Cert,
					 IN UINTN CertSize,
					 OUT UINT8 **SingleX509Cert)
{
	struct lc_x509_certificate *parsed_cert;

	/* Check input parameters. */
	if (Cert == NULL || SingleX509Cert == NULL || CertSize > INT_MAX)
		return FALSE;

	parsed_cert = AllocatePool(sizeof(struct lc_x509_certificate));
	if (!parsed_cert)
		return FALSE;

	/* Read DER-encoded X509 Certificate and Construct X509 object. */
	if (lc_x509_cert_decode(parsed_cert, Cert, CertSize)) {
		FreePool(parsed_cert);
		return FALSE;
	}

	*SingleX509Cert = (UINT8 *) parsed_cert;

	return TRUE;
}

/**
 * Release the specified X509 object.
 *
 * If X509Cert is NULL, then return FALSE.
 *
 * @param[in]  X509Cert  Pointer to the X509 object to be released.
 */
VOID EFIAPI X509Free (IN VOID *X509Cert)
{
	struct lc_x509_certificate *parsed_cert;

	/* Check input parameters. */
	if (X509Cert == NULL)
		return;

	parsed_cert = X509Cert;
  
	/* Free OpenSSL X509 object. */
	lc_x509_cert_clear(parsed_cert);
	FreePool(parsed_cert);
}
