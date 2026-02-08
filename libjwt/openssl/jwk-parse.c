/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>

#include <openssl/opensslv.h>
#include <jwt.h>
#include "jwt-private.h"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "openssl/jwt-openssl.h"

/* Common helper: write PEM from EVP_PKEY and set item fields */
static int pkey_to_pem(EVP_PKEY *pkey, jwk_item_t *item, int priv)
{
	BIO *bio = NULL;
	char *src = NULL, *dest = NULL;
	long len;
	int ret = 0;

	item->provider = JWT_CRYPTO_OPS_OPENSSL;
	item->provider_data = pkey;
	item->bits = EVP_PKEY_bits(pkey);

	/* PEM generation is optional - key is already usable */
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return 0; // LCOV_EXCL_LINE

	if (priv)
		ret = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0,
					       NULL, NULL);
	else
		ret = PEM_write_bio_PUBKEY(bio, pkey);

	if (!ret) {
		// LCOV_EXCL_START
		BIO_free(bio);
		return 0;
		// LCOV_EXCL_STOP
	}

	len = BIO_get_mem_data(bio, &src);
	dest = OPENSSL_malloc(len + 1);
	if (dest == NULL) {
		// LCOV_EXCL_START
		BIO_free(bio);
		return 0;
		// LCOV_EXCL_STOP
	}

	memcpy(dest, src, len);
	dest[len] = '\0';
	item->pem = dest;

	BIO_free(bio);
	return 0;
}

/* Helper: create BIGNUM from raw bytes */
static BIGNUM *raw_to_bn(const jwk_raw_t *raw)
{
	if (raw->bin == NULL || raw->len <= 0)
		return NULL;
	return BN_bin2bn(raw->bin, raw->len, NULL);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * ==================== OpenSSL 3.0+ Path ====================
 * Uses OSSL_PARAM_BLD and EVP_PKEY_fromdata
 */

static int pctx_to_pkey(EVP_PKEY_CTX *pctx, OSSL_PARAM *params,
			jwk_item_t *item, int priv)
{
	EVP_PKEY *pkey = NULL;
	int ret;

	ret = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params);

	if (ret <= 0 || pkey == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Unable to create PEM from pkey");
		return -1;
		// LCOV_EXCL_STOP
	}

	return pkey_to_pem(pkey, item, priv);
}

/* Sets a param for the public EC key */
static void *set_ec_pub_key_ossl3(OSSL_PARAM_BLD *build,
				  const jwk_ec_raw_t *raw,
				  const char *ossl_curve)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL;
	int nid;
	size_t pub_key_len = 0;
	unsigned char *pub_key = NULL;

	x = BN_bin2bn(raw->x.bin, raw->x.len, NULL);
	y = BN_bin2bn(raw->y.bin, raw->y.len, NULL);
	if (x == NULL || y == NULL)
		goto cleanup;

	nid = OBJ_sn2nid(ossl_curve);
	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL)
		goto cleanup;

	point = EC_POINT_new(group);
	if (point == NULL)
		goto cleanup; // LCOV_EXCL_LINE

	if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
		goto cleanup;

	pub_key_len = EC_POINT_point2buf(group, point,
					 POINT_CONVERSION_UNCOMPRESSED,
					 &pub_key, NULL);
	if (pub_key_len == 0)
		goto cleanup; // LCOV_EXCL_LINE

	OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
					 pub_key, pub_key_len);

cleanup:
	EC_POINT_free(point);
	EC_GROUP_free(group);
	BN_free(x);
	BN_free(y);

	return pub_key;
}

static int openssl3_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw)
{
	OSSL_PARAM_BLD *build = NULL;
	BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL,
		*bn_q = NULL, *bn_dp = NULL, *bn_dq = NULL, *bn_qi = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int ret = -1;

	/* Always create a plain RSA key regardless of the JWK "alg"
	 * field. A regular EVP_PKEY_RSA key can perform both PKCS#1
	 * v1.5 (RS*) and PSS (PS*) operations — the padding mode is
	 * selected at signing time, not at key creation. Creating an
	 * EVP_PKEY_RSA_PSS key would needlessly restrict the key to
	 * PSS-only, breaking RS* algorithms with the same key. */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating pkey context");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error preparing context for data");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating param build");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	bn_n = raw_to_bn(&raw->n);
	bn_e = raw_to_bn(&raw->e);
	if (!bn_n || !bn_e) {
		jwt_write_error(item, "Error decoding pub components");
		goto cleanup;
	}
	OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, bn_n);
	OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_E, bn_e);

	if (raw->is_private) {
		bn_d = raw_to_bn(&raw->d);
		bn_p = raw_to_bn(&raw->p);
		bn_q = raw_to_bn(&raw->q);
		bn_dp = raw_to_bn(&raw->dp);
		bn_dq = raw_to_bn(&raw->dq);
		bn_qi = raw_to_bn(&raw->qi);
		if (!bn_d || !bn_p || !bn_q || !bn_dp || !bn_dq || !bn_qi) {
			jwt_write_error(item,
					"Error decoding priv components");
			goto cleanup;
		}
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_D, bn_d);
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_FACTOR1,
				       bn_p);
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_FACTOR2,
				       bn_q);
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_EXPONENT1,
				       bn_dp);
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_EXPONENT2,
				       bn_dq);
		OSSL_PARAM_BLD_push_BN(build,
				       OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn_qi);
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error building params");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	ret = pctx_to_pkey(pctx, params, item, raw->is_private);

cleanup:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	EVP_PKEY_CTX_free(pctx);
	BN_free(bn_n);
	BN_free(bn_e);
	BN_free(bn_d);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_dp);
	BN_free(bn_dq);
	BN_free(bn_qi);

	return ret;
}

static int openssl3_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw)
{
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *build = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	BIGNUM *bn_d = NULL;
	const char *ossl_crv;
	int ret = -1;
	void *pub_key = NULL;

	/* Map JWK curve names to OpenSSL names */
	if (!strcmp(raw->curve, "P-256"))
		ossl_crv = "prime256v1";
	else if (!strcmp(raw->curve, "P-384"))
		ossl_crv = "secp384r1";
	else if (!strcmp(raw->curve, "P-521"))
		ossl_crv = "secp521r1";
	else
		ossl_crv = raw->curve;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating pkey context");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error preparing context for data");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating param build");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME,
					ossl_crv, strlen(ossl_crv));
	pub_key = set_ec_pub_key_ossl3(build, raw, ossl_crv);
	if (pub_key == NULL) {
		jwt_write_error(item,
				"Error generating pub key from components");
		goto cleanup;
	}

	if (raw->is_private) {
		bn_d = raw_to_bn(&raw->d);
		if (bn_d == NULL) {
		// LCOV_EXCL_START
			jwt_write_error(item, "Error parsing component d");
			goto cleanup;
		// LCOV_EXCL_STOP
	}
		OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_PRIV_KEY, bn_d);
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error build params");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	ret = pctx_to_pkey(pctx, params, item, raw->is_private);

cleanup:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	OPENSSL_free(pub_key);
	EVP_PKEY_CTX_free(pctx);
	BN_free(bn_d);

	return ret;
}

static int openssl3_process_eddsa(jwk_item_t *item,
				  const jwk_eddsa_raw_t *raw)
{
	OSSL_PARAM_BLD *build = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int ret = -1;

	if (!strcmp(raw->curve, "Ed25519"))
		pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
	else if (!strcmp(raw->curve, "Ed448"))
		pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED448", NULL);
	else {
		jwt_write_error(item,
                        "Unknown curve [%s] (note, curves are case sensitive)",
			raw->curve);
		return -1;
	}

	if (pctx == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating pkey context");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error starting pkey init from data");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	build = OSSL_PARAM_BLD_new();
	if (build == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating params build");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (raw->is_private) {
		OSSL_PARAM_BLD_push_octet_string(build,
			OSSL_PKEY_PARAM_PRIV_KEY, raw->key.bin, raw->key.len);
	} else {
		OSSL_PARAM_BLD_push_octet_string(build,
			OSSL_PKEY_PARAM_PUB_KEY, raw->key.bin, raw->key.len);
	}

	params = OSSL_PARAM_BLD_to_param(build);
	if (params == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating build params");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	ret = pctx_to_pkey(pctx, params, item, raw->is_private);

cleanup:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(build);
	EVP_PKEY_CTX_free(pctx);

	return ret;
}

#else /* OpenSSL < 3.0.0 */
/*
 * ==================== OpenSSL 1.1.x Path ====================
 * Uses legacy RSA/EC_KEY APIs
 */

static int openssl11_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL;
	BIGNUM *bn_p = NULL, *bn_q = NULL;
	BIGNUM *bn_dp = NULL, *bn_dq = NULL, *bn_qi = NULL;
	int ret = -1;

	rsa = RSA_new();
	if (rsa == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating RSA key");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	bn_n = raw_to_bn(&raw->n);
	bn_e = raw_to_bn(&raw->e);
	if (!bn_n || !bn_e) {
		jwt_write_error(item, "Error decoding pub components");
		goto cleanup;
	}

	if (raw->is_private) {
		bn_d = raw_to_bn(&raw->d);
		if (!bn_d) {
			jwt_write_error(item, "Error decoding priv component d");
			goto cleanup;
		}
	}

	/* RSA_set0_key takes ownership of BIGNUMs on success */
	if (!RSA_set0_key(rsa, bn_n, bn_e, bn_d)) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error setting RSA key components");
		goto cleanup;
		// LCOV_EXCL_STOP
	}
	/* Ownership transferred - don't free these on success */
	bn_n = NULL;
	bn_e = NULL;
	bn_d = NULL;

	if (raw->is_private) {
		bn_p = raw_to_bn(&raw->p);
		bn_q = raw_to_bn(&raw->q);
		if (!bn_p || !bn_q) {
			jwt_write_error(item,
					"Error decoding RSA factors");
			goto cleanup;
		}
		if (!RSA_set0_factors(rsa, bn_p, bn_q)) {
			// LCOV_EXCL_START
			jwt_write_error(item,
					"Error setting RSA factors");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
		bn_p = NULL;
		bn_q = NULL;

		bn_dp = raw_to_bn(&raw->dp);
		bn_dq = raw_to_bn(&raw->dq);
		bn_qi = raw_to_bn(&raw->qi);
		if (!bn_dp || !bn_dq || !bn_qi) {
			jwt_write_error(item,
					"Error decoding CRT params");
			goto cleanup;
		}
		if (!RSA_set0_crt_params(rsa, bn_dp, bn_dq, bn_qi)) {
			// LCOV_EXCL_START
			jwt_write_error(item,
					"Error setting RSA CRT params");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
		bn_dp = NULL;
		bn_dq = NULL;
		bn_qi = NULL;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating EVP_PKEY");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	/* EVP_PKEY_assign_RSA takes ownership of rsa on success */
	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		// LCOV_EXCL_START
		EVP_PKEY_free(pkey);
		jwt_write_error(item, "Error assigning RSA to EVP_PKEY");
		goto cleanup;
		// LCOV_EXCL_STOP
	}
	rsa = NULL; /* Ownership transferred */

	ret = pkey_to_pem(pkey, item, raw->is_private);
	/* pkey ownership transferred to item via pkey_to_pem */
	return ret;

cleanup:
	RSA_free(rsa);
	BN_free(bn_n);
	BN_free(bn_e);
	BN_free(bn_d);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_dp);
	BN_free(bn_dq);
	BN_free(bn_qi);

	return ret;
}

static int openssl11_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw)
{
	EC_KEY *ec_key = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *bn_x = NULL, *bn_y = NULL, *bn_d = NULL;
	int nid;
	const char *ossl_crv;
	int ret = -1;

	/* Map JWK curve names to OpenSSL names */
	if (!strcmp(raw->curve, "P-256"))
		ossl_crv = "prime256v1";
	else if (!strcmp(raw->curve, "P-384"))
		ossl_crv = "secp384r1";
	else if (!strcmp(raw->curve, "P-521"))
		ossl_crv = "secp521r1";
	else
		ossl_crv = raw->curve;

	nid = OBJ_sn2nid(ossl_crv);
	if (nid == NID_undef) {
		jwt_write_error(item, "Unknown EC curve: %s", raw->curve);
		return -1;
	}

	ec_key = EC_KEY_new_by_curve_name(nid);
	if (ec_key == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating EC key");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating EC group");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	bn_x = raw_to_bn(&raw->x);
	bn_y = raw_to_bn(&raw->y);
	if (!bn_x || !bn_y) {
		jwt_write_error(item, "Error decoding EC public components");
		goto cleanup;
	}

	point = EC_POINT_new(group);
	if (point == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error creating EC point");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, point, bn_x, bn_y,
						 NULL)) {
		jwt_write_error(item, "Error setting EC point coordinates");
		goto cleanup;
	}

	if (!EC_KEY_set_public_key(ec_key, point)) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error setting EC public key");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	if (raw->is_private) {
		bn_d = raw_to_bn(&raw->d);
		if (!bn_d) {
			jwt_write_error(item,
					"Error decoding EC private component");
			goto cleanup;
		}
		if (!EC_KEY_set_private_key(ec_key, bn_d)) {
			// LCOV_EXCL_START
			jwt_write_error(item, "Error setting EC private key");
			goto cleanup;
			// LCOV_EXCL_STOP
		}
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		// LCOV_EXCL_START
		jwt_write_error(item, "Error allocating EVP_PKEY");
		goto cleanup;
		// LCOV_EXCL_STOP
	}

	/* EVP_PKEY_assign_EC_KEY takes ownership of ec_key on success */
	if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
		// LCOV_EXCL_START
		EVP_PKEY_free(pkey);
		jwt_write_error(item, "Error assigning EC key to EVP_PKEY");
		goto cleanup;
		// LCOV_EXCL_STOP
	}
	ec_key = NULL; /* Ownership transferred */

	ret = pkey_to_pem(pkey, item, raw->is_private);
	/* pkey ownership transferred to item via pkey_to_pem */
	EC_GROUP_free(group);
	EC_POINT_free(point);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn_d);
	return ret;

cleanup:
	EC_KEY_free(ec_key);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn_d);

	return ret;
}

/* EdDSA requires OpenSSL >= 1.1.1 */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
static int openssl11_process_eddsa(jwk_item_t *item,
				   const jwk_eddsa_raw_t *raw)
{
	EVP_PKEY *pkey = NULL;
	int nid;

	if (!strcmp(raw->curve, "Ed25519"))
		nid = EVP_PKEY_ED25519;
	else if (!strcmp(raw->curve, "Ed448"))
		nid = EVP_PKEY_ED448;
	else {
		jwt_write_error(item,
			"Unknown curve [%s] (note, curves are case sensitive)",
			raw->curve);
		return -1;
	}

	if (raw->is_private)
		pkey = EVP_PKEY_new_raw_private_key(nid, NULL,
						    raw->key.bin,
						    raw->key.len);
	else
		pkey = EVP_PKEY_new_raw_public_key(nid, NULL,
						   raw->key.bin,
						   raw->key.len);

	if (pkey == NULL) {
		jwt_write_error(item, "Error creating EdDSA key");
		return -1;
	}

	return pkey_to_pem(pkey, item, raw->is_private);
}
#else
static int openssl11_process_eddsa(jwk_item_t *item,
				   const jwk_eddsa_raw_t *raw)
{
	(void)raw;
	jwt_write_error(item, "EdDSA requires OpenSSL >= 1.1.1");
	return -1;
}
#endif

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/*
 * ==================== Public API ====================
 * Dispatch to version-specific implementations
 */

JWT_NO_EXPORT
int openssl_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return openssl3_process_rsa(item, raw);
#else
	return openssl11_process_rsa(item, raw);
#endif
}

JWT_NO_EXPORT
int openssl_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return openssl3_process_ec(item, raw);
#else
	return openssl11_process_ec(item, raw);
#endif
}

JWT_NO_EXPORT
int openssl_process_eddsa(jwk_item_t *item, const jwk_eddsa_raw_t *raw)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return openssl3_process_eddsa(item, raw);
#else
	return openssl11_process_eddsa(item, raw);
#endif
}

JWT_NO_EXPORT
void openssl_process_item_free(jwk_item_t *item)
{
	if (item == NULL || item->provider != JWT_CRYPTO_OPS_OPENSSL)
		return;

	EVP_PKEY_free(item->provider_data);

	/* Scrub PEM before freeing — may contain private key material */
	if (item->pem)
		OPENSSL_clear_free(item->pem, strlen(item->pem));

	item->pem = NULL;
	item->provider_data = NULL;
	item->provider = JWT_CRYPTO_OPS_NONE;
}
