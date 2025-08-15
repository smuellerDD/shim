/** @file
 * Authenticode Portable Executable Signature Verification using leancrypto.
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
 * Verifies the validity of a PE/COFF Authenticode Signature as described in
 * "Windows Authenticode Portable Executable Signature Format".
 *
 * If AuthData is NULL, then return FALSE.
 * If ImageHash is NULL, then return FALSE.
 *
 * Caution: This function may receive untrusted input.
 * PE/COFF Authenticode is external input, so this function will do basic check
 * for Authenticode data structure.
 *
 * @param[in] AuthData Pointer to the Authenticode Signature retrieved from
 *		       signed PE/COFF image to be verified.
 * @param[in] DataSize Size of the Authenticode Signature in bytes.
 * @param[in] TrustedCert Pointer to a trusted/root certificate encoded in DER,
 *			  which is used for certificate chain verification.
 * @param[in] CertSize Size of the trusted certificate in bytes.
 * @param[in] ImageData Pointer to the original image file data value.
 * @param[in] ImageSize Size of Image data value in bytes.
 *
 * @retval TRUE The specified Authenticode Signature is valid.
 * @retval FALSE Invalid Authenticode Signature.
 */
BOOLEAN EFIAPI AuthenticodeVerify (IN CONST UINT8 *AuthData,
				   IN UINTN DataSize,
				   IN CONST UINT8 *TrustedCert,
				   IN UINTN CertSize,
				   IN CONST UINT8 *ImageData,
				   IN UINTN ImageSize)
{
	struct lc_pkcs7_trust_store trust_store;
	struct lc_x509_certificate x509;
	struct lc_pkcs7_message pkcs7;
#if defined(ENABLE_CODESIGN_EKU)
	struct lc_verify_rules verify_rules = {
		.required_keyusage = 0,
		.required_eku = LC_KEY_EKU_CODE_SIGNING |
				LC_KEY_EKU_MODULE_SIGNING,
	};
	struct lc_verify_rules *verify_rules_p = &verify_rules;
#else
	struct lc_verify_rules *verify_rules_p = NULL;
#endif
	BOOLEAN Status = FALSE;

	/* Check input parameters. */
	if ((AuthData == NULL) || (TrustedCert == NULL) ||
	    (ImageData == NULL)) {
		return FALSE;
	}

	if ((DataSize > INT_MAX) || (CertSize > INT_MAX) ||
	    (ImageSize > INT_MAX)) {
		return FALSE;
	}

	/* Load trust store - i.e. CA certificate */
	if (lc_x509_cert_decode(&x509, TrustedCert, CertSize))
		return AuthenticodeVerify_openssl(AuthData, DataSize,
						  TrustedCert, CertSize,
						  ImageData, ImageSize);

	if (lc_pkcs7_trust_store_add(&trust_store, &x509))
		goto out;

	/* Load PKCS7 message */
	if (lc_pkcs7_decode(&pkcs7, AuthData, DataSize))
		goto out;

	/* Supply detached data - i.e. data to be verified */
	if (lc_pkcs7_supply_detached_data(&pkcs7, ImageData, ImageSize))
		goto out;

	/* Verify the data */
	if (lc_pkcs7_verify(&pkcs7, &trust_store, verify_rules_p))
		goto out;

out:
	lc_x509_cert_clear(&x509);
	lc_pkcs7_message_clear(&pkcs7);
	lc_pkcs7_trust_store_clear(&trust_store);
	return Status;
}
