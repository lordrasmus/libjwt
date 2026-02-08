/* Copyright (C) 2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jwt.h>

#include "jwt-private.h"

/* Helper: copy GnuTLS datum to jwt_malloc'd PEM string */
static char *datum_to_pem(gnutls_datum_t *out)
{
	char *pem = jwt_malloc(out->size + 1);
	if (pem == NULL)
		return NULL;
	memcpy(pem, out->data, out->size);
	pem[out->size] = '\0';
	return pem;
}

/* Helper: export a GnuTLS public key to PEM and populate item fields */
static int pubkey_to_pem(gnutls_pubkey_t pubkey, jwk_item_t *item)
{
	gnutls_datum_t out = { NULL, 0 };
	unsigned int bits = 0;
	int ret;

	gnutls_pubkey_get_pk_algorithm(pubkey, &bits);

	ret = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_PEM, &out);
	gnutls_pubkey_deinit(pubkey);

	if (ret < 0) {
		jwt_write_error(item,
			"GnuTLS: failed to export public key PEM");
		return -1;
	}

	item->pem = datum_to_pem(&out);
	gnutls_free(out.data);

	if (item->pem == NULL)
		return -1;

	item->bits = bits;
	item->provider = JWT_CRYPTO_OPS_GNUTLS;

	return 0;
}

/* Helper: export a GnuTLS private key to PEM and populate item fields.
 * Uses gnutls_privkey_export_x509 + gnutls_x509_privkey_export2.
 * NOTE: This does NOT work for EdDSA keys (GnuTLS bug) - EdDSA uses
 * a separate PKCS#8 DER construction path. */
static int privkey_to_pem(gnutls_privkey_t privkey, jwk_item_t *item)
{
	gnutls_x509_privkey_t x509_key = NULL;
	gnutls_datum_t out = { NULL, 0 };
	unsigned int bits = 0;
	int ret;

	gnutls_privkey_get_pk_algorithm(privkey, &bits);

	ret = gnutls_privkey_export_x509(privkey, &x509_key);
	gnutls_privkey_deinit(privkey);

	if (ret < 0) {
		jwt_write_error(item,
			"GnuTLS: failed to export privkey to x509");
		return -1;
	}

	ret = gnutls_x509_privkey_export2(x509_key, GNUTLS_X509_FMT_PEM,
					   &out);
	gnutls_x509_privkey_deinit(x509_key);

	if (ret < 0) {
		jwt_write_error(item,
			"GnuTLS: failed to export private key PEM");
		return -1;
	}

	item->pem = datum_to_pem(&out);
	gnutls_free(out.data);

	if (item->pem == NULL)
		return -1;

	item->bits = bits;
	item->provider = JWT_CRYPTO_OPS_GNUTLS;

	return 0;
}

/*
 * EdDSA private key export via PKCS#8 DER construction.
 *
 * GnuTLS has a bug where gnutls_privkey_export_x509() segfaults on
 * EdDSA keys imported via gnutls_privkey_import_ecc_raw(). Work around
 * this by constructing the PKCS#8 DER envelope manually and importing
 * it via gnutls_x509_privkey_import_pkcs8().
 *
 * Ed25519 PKCS#8 DER:
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
 *              OCTET STRING { OCTET STRING <32 bytes> } }
 *   = 16-byte prefix + 32-byte key = 48 bytes
 *
 * Ed448 PKCS#8 DER:
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.113 },
 *              OCTET STRING { OCTET STRING <57 bytes> } }
 *   = 16-byte prefix + 57-byte key = 73 bytes
 */
static const unsigned char ed25519_pkcs8_prefix[] = {
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
};
#define ED25519_KEY_LEN 32
#define ED25519_PKCS8_LEN (sizeof(ed25519_pkcs8_prefix) + ED25519_KEY_LEN)

static const unsigned char ed448_pkcs8_prefix[] = {
	0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x71, 0x04, 0x3b, 0x04, 0x39
};
#define ED448_KEY_LEN 57
#define ED448_PKCS8_LEN (sizeof(ed448_pkcs8_prefix) + ED448_KEY_LEN)

static int eddsa_privkey_to_pem(const unsigned char *prefix, int prefix_len,
				const unsigned char *raw_key, int key_len,
				int expected_len, jwk_item_t *item)
{
	unsigned char der_buf[ED448_PKCS8_LEN]; /* large enough for both */
	gnutls_datum_t der, out = { NULL, 0 };
	gnutls_x509_privkey_t x509_key = NULL;
	int rc = -1;

	if (key_len != expected_len) {
		jwt_write_error(item,
			"GnuTLS: EdDSA key length mismatch: expected %d, got %d",
			expected_len, key_len);
		goto zeroize;
	}

	memcpy(der_buf, prefix, prefix_len);
	memcpy(der_buf + prefix_len, raw_key, key_len);
	der.data = der_buf;
	der.size = prefix_len + key_len;

	if (gnutls_x509_privkey_init(&x509_key) < 0) {
		jwt_write_error(item,
			"GnuTLS: error initializing x509 privkey");
		goto zeroize;
	}

	if (gnutls_x509_privkey_import_pkcs8(x509_key, &der,
					     GNUTLS_X509_FMT_DER,
					     NULL, GNUTLS_PKCS_PLAIN) < 0) {
		jwt_write_error(item,
			"GnuTLS: error importing EdDSA PKCS#8 key");
		goto zeroize;
	}

	if (gnutls_x509_privkey_export2_pkcs8(x509_key, GNUTLS_X509_FMT_PEM,
					      NULL, 0, &out) < 0) {
		jwt_write_error(item,
			"GnuTLS: error exporting EdDSA private key PEM");
		goto zeroize;
	}

	item->pem = datum_to_pem(&out);
	gnutls_free(out.data);

	if (item->pem == NULL)
		goto zeroize;

	item->bits = key_len * 8;
	item->provider = JWT_CRYPTO_OPS_GNUTLS;
	rc = 0;

zeroize:
	/* Scrub private key material from stack buffer */
	memset(der_buf, 0, sizeof(der_buf));
	if (x509_key)
		gnutls_x509_privkey_deinit(x509_key);
	return rc;
}

JWT_NO_EXPORT
int gnutls_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw)
{
	gnutls_datum_t m  = { raw->n.bin,  raw->n.len  };
	gnutls_datum_t e  = { raw->e.bin,  raw->e.len  };
	gnutls_datum_t d  = { raw->d.bin,  raw->d.len  };
	gnutls_datum_t p  = { raw->p.bin,  raw->p.len  };
	gnutls_datum_t q  = { raw->q.bin,  raw->q.len  };
	gnutls_datum_t dp = { raw->dp.bin, raw->dp.len };
	gnutls_datum_t dq = { raw->dq.bin, raw->dq.len };
	gnutls_datum_t qi = { raw->qi.bin, raw->qi.len };
	int ret;

	if (raw->is_private) {
		gnutls_privkey_t privkey;

		ret = gnutls_privkey_init(&privkey);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing privkey");
			return -1;
		}

		ret = gnutls_privkey_import_rsa_raw(privkey,
			&m, &e, &d, &p, &q, &qi, &dp, &dq);
		if (ret < 0) {
			gnutls_privkey_deinit(privkey);
			jwt_write_error(item,
				"GnuTLS: error importing RSA private key");
			return -1;
		}

		return privkey_to_pem(privkey, item);
	} else {
		gnutls_pubkey_t pubkey;

		ret = gnutls_pubkey_init(&pubkey);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing pubkey");
			return -1;
		}

		ret = gnutls_pubkey_import_rsa_raw(pubkey, &m, &e);
		if (ret < 0) {
			gnutls_pubkey_deinit(pubkey);
			jwt_write_error(item,
				"GnuTLS: error importing RSA public key");
			return -1;
		}

		return pubkey_to_pem(pubkey, item);
	}
}

JWT_NO_EXPORT
int gnutls_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw)
{
	gnutls_ecc_curve_t curve;
	gnutls_datum_t x = { raw->x.bin, raw->x.len };
	gnutls_datum_t y = { raw->y.bin, raw->y.len };
	gnutls_datum_t k = { raw->d.bin, raw->d.len };
	int ret;

	/* Accept both JWK names (P-256 etc.) and OpenSSL names
	 * (prime256v1 etc.) since some test vectors use the latter.
	 * Note: secp256k1 is not supported by GnuTLS. */
	if (!strcmp(raw->curve, "P-256") ||
	    !strcmp(raw->curve, "prime256v1"))
		curve = GNUTLS_ECC_CURVE_SECP256R1;
	else if (!strcmp(raw->curve, "P-384") ||
		 !strcmp(raw->curve, "secp384r1"))
		curve = GNUTLS_ECC_CURVE_SECP384R1;
	else if (!strcmp(raw->curve, "P-521") ||
		 !strcmp(raw->curve, "secp521r1"))
		curve = GNUTLS_ECC_CURVE_SECP521R1;
	else {
		jwt_write_error(item,
			"GnuTLS: unsupported EC curve: %s", raw->curve);
		return -1;
	}

	/* GnuTLS does not validate EC point coordinates on raw import.
	 * Validate explicitly via a temporary pubkey to reject keys
	 * with points not on the curve (matches OpenSSL/MbedTLS). */
	{
		gnutls_pubkey_t vpub;

		ret = gnutls_pubkey_init(&vpub);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing validation key");
			return -1;
		}

		ret = gnutls_pubkey_import_ecc_raw(vpub, curve, &x, &y);
		if (ret < 0) {
			gnutls_pubkey_deinit(vpub);
			jwt_write_error(item,
				"GnuTLS: error importing EC public key");
			return -1;
		}

		ret = gnutls_pubkey_verify_params(vpub);
		gnutls_pubkey_deinit(vpub);

		if (ret < 0) {
			jwt_write_error(item,
				"Error generating pub key from components");
			return -1;
		}
	}

	if (raw->is_private) {
		gnutls_privkey_t privkey;

		ret = gnutls_privkey_init(&privkey);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing privkey");
			return -1;
		}

		ret = gnutls_privkey_import_ecc_raw(privkey, curve,
						    &x, &y, &k);
		if (ret < 0) {
			gnutls_privkey_deinit(privkey);
			jwt_write_error(item,
				"GnuTLS: error importing EC private key");
			return -1;
		}

		ret = privkey_to_pem(privkey, item);

		/* GnuTLS computes P-521 key size as 66 bytes * 8 = 528 bits,
		 * but the standard key size is 521. The library checks for
		 * exactly 521 bits in jwt.c, so we must correct this. */
		if (ret == 0 && curve == GNUTLS_ECC_CURVE_SECP521R1)
			item->bits = 521;

		return ret;
	} else {
		gnutls_pubkey_t pubkey;

		ret = gnutls_pubkey_init(&pubkey);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing pubkey");
			return -1;
		}

		ret = gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y);
		if (ret < 0) {
			gnutls_pubkey_deinit(pubkey);
			jwt_write_error(item,
				"GnuTLS: error importing EC public key");
			return -1;
		}

		ret = pubkey_to_pem(pubkey, item);

		/* See above: correct P-521 bit size from 528 to 521 */
		if (ret == 0 && curve == GNUTLS_ECC_CURVE_SECP521R1)
			item->bits = 521;

		return ret;
	}
}

JWT_NO_EXPORT
int gnutls_process_eddsa(jwk_item_t *item, const jwk_eddsa_raw_t *raw)
{
	gnutls_ecc_curve_t curve;
	gnutls_datum_t key = { raw->key.bin, raw->key.len };
	int ret;

	if (!strcmp(raw->curve, "Ed25519"))
		curve = GNUTLS_ECC_CURVE_ED25519;
	else if (!strcmp(raw->curve, "Ed448"))
		curve = GNUTLS_ECC_CURVE_ED448;
	else {
		jwt_write_error(item,
			"GnuTLS: unknown EdDSA curve: %s", raw->curve);
		return -1;
	}

	if (raw->is_private) {
		/*
		 * Use PKCS#8 DER construction to work around GnuTLS bug
		 * where gnutls_privkey_export_x509() segfaults on EdDSA
		 * keys imported via gnutls_privkey_import_ecc_raw().
		 */
		if (curve == GNUTLS_ECC_CURVE_ED25519) {
			return eddsa_privkey_to_pem(ed25519_pkcs8_prefix,
				sizeof(ed25519_pkcs8_prefix),
				raw->key.bin, raw->key.len,
				ED25519_KEY_LEN, item);
		} else {
			return eddsa_privkey_to_pem(ed448_pkcs8_prefix,
				sizeof(ed448_pkcs8_prefix),
				raw->key.bin, raw->key.len,
				ED448_KEY_LEN, item);
		}
	} else {
		gnutls_pubkey_t pubkey;

		ret = gnutls_pubkey_init(&pubkey);
		if (ret < 0) {
			jwt_write_error(item,
				"GnuTLS: error initializing pubkey");
			return -1;
		}

		ret = gnutls_pubkey_import_ecc_raw(pubkey, curve,
						   &key, NULL);
		if (ret < 0) {
			gnutls_pubkey_deinit(pubkey);
			jwt_write_error(item,
				"GnuTLS: error importing EdDSA public key");
			return -1;
		}

		return pubkey_to_pem(pubkey, item);
	}
}

JWT_NO_EXPORT
void gnutls_process_item_free(jwk_item_t *item)
{
	if (item == NULL || item->provider != JWT_CRYPTO_OPS_GNUTLS)
		return;

	/* Scrub PEM before freeing — may contain private key material */
	if (item->pem)
		memset(item->pem, 0, strlen(item->pem));
	jwt_freemem(item->pem);

	item->pem = NULL;
	item->provider = JWT_CRYPTO_OPS_NONE;
}
