/* Copyright (C) 2015-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <mbedtls/platform_util.h>

#include <jwt.h>

#include "jwt-private.h"
#include "jwt-mbedtls.h"

/* Convert an mbedtls_pk_context to PEM and set item fields.
 * The pk context is heap-allocated and stored in item->provider_data. */
static int pk_to_pem(mbedtls_pk_context *pk, jwk_item_t *item, int priv)
{
	unsigned char buf[16384];
	int ret;
	size_t len;
	char *pem;
	mbedtls_pk_context *pk_copy;

	/* Write PEM to stack buffer */
	if (priv)
		ret = mbedtls_pk_write_key_pem(pk, buf, sizeof(buf));
	else
		ret = mbedtls_pk_write_pubkey_pem(pk, buf, sizeof(buf));

	if (ret != 0) {
		jwt_write_error(item, "Error writing PEM from key");
		mbedtls_platform_zeroize(buf, sizeof(buf));
		mbedtls_pk_free(pk);
		return -1;
	}

	len = strlen((char *)buf);
	pem = jwt_malloc(len + 1);
	if (pem == NULL) {
		mbedtls_pk_free(pk);
		return -1;
	}
	memcpy(pem, buf, len + 1);
	mbedtls_platform_zeroize(buf, sizeof(buf));

	/* Heap-allocate a copy of the pk context for provider_data */
	pk_copy = jwt_malloc(sizeof(mbedtls_pk_context));
	if (pk_copy == NULL) {
		jwt_freemem(pem);
		mbedtls_pk_free(pk);
		return -1;
	}
	/* Move the pk context into the heap copy */
	*pk_copy = *pk;
	/* Zero the stack pk so mbedtls_pk_free on it is a no-op */
	memset(pk, 0, sizeof(*pk));

	item->pem = pem;
	item->provider_data = pk_copy;
	item->provider = JWT_CRYPTO_OPS_MBEDTLS;
	item->bits = mbedtls_pk_get_bitlen(pk_copy);

	return 0;
}

JWT_NO_EXPORT
int mbedtls_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw)
{
	mbedtls_pk_context pk;
	mbedtls_rsa_context *rsa;
	mbedtls_mpi N, E, D, P, Q;
	int ret = -1;

	mbedtls_pk_init(&pk);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);

	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) {
		jwt_write_error(item, "Error setting up RSA pk context");
		goto cleanup;
	}

	/* Read public components */
	if (mbedtls_mpi_read_binary(&N, raw->n.bin, raw->n.len) ||
	    mbedtls_mpi_read_binary(&E, raw->e.bin, raw->e.len)) {
		jwt_write_error(item, "Error decoding pub components");
		goto cleanup;
	}

	if (raw->is_private) {
		if (mbedtls_mpi_read_binary(&D, raw->d.bin, raw->d.len)) {
			jwt_write_error(item,
					"Error decoding priv component d");
			goto cleanup;
		}

		/* Read P and Q if available */
		if (raw->p.bin && raw->p.len > 0 &&
		    mbedtls_mpi_read_binary(&P, raw->p.bin, raw->p.len)) {
			jwt_write_error(item,
					"Error decoding priv component p");
			goto cleanup;
		}
		if (raw->q.bin && raw->q.len > 0 &&
		    mbedtls_mpi_read_binary(&Q, raw->q.bin, raw->q.len)) {
			jwt_write_error(item,
					"Error decoding priv component q");
			goto cleanup;
		}
	}

	rsa = mbedtls_pk_rsa(pk);

	if (raw->is_private) {
		/* Import all components for private key */
		if (mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E)) {
			jwt_write_error(item,
					"Error importing RSA components");
			goto cleanup;
		}

		/* Complete the RSA key (derives missing CRT params) */
		if (mbedtls_rsa_complete(rsa)) {
			jwt_write_error(item, "Error completing RSA key");
			goto cleanup;
		}
	} else {
		/* Public key only: import N and E */
		if (mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E)) {
			jwt_write_error(item,
					"Error importing RSA pub components");
			goto cleanup;
		}
	}

	ret = pk_to_pem(&pk, item, raw->is_private);

cleanup:
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	if (ret != 0)
		mbedtls_pk_free(&pk);

	return ret;
}

/* Curve lookup table */
struct ec_curve_info {
	const char *jwk_name;
	mbedtls_ecp_group_id grp_id;
	size_t coord_len; /* bytes per coordinate */
};

static const struct ec_curve_info ec_curves[] = {
	{ "P-256",      MBEDTLS_ECP_DP_SECP256R1, 32 },
	{ "P-384",      MBEDTLS_ECP_DP_SECP384R1, 48 },
	{ "P-521",      MBEDTLS_ECP_DP_SECP521R1, 66 },
	{ "secp256k1",  MBEDTLS_ECP_DP_SECP256K1, 32 },
	{ "prime256v1", MBEDTLS_ECP_DP_SECP256R1, 32 },
	{ "secp384r1",  MBEDTLS_ECP_DP_SECP384R1, 48 },
	{ "secp521r1",  MBEDTLS_ECP_DP_SECP521R1, 66 },
};

JWT_NO_EXPORT
int mbedtls_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw)
{
	mbedtls_pk_context pk;
	mbedtls_ecp_keypair *ec;
	const struct ec_curve_info *ci = NULL;
	unsigned char *pt_buf = NULL;
	size_t pt_len;
	unsigned int i;
	int ret = -1;

	/* Find curve */
	for (i = 0; i < ARRAY_SIZE(ec_curves); i++) {
		if (!strcmp(raw->curve, ec_curves[i].jwk_name)) {
			ci = &ec_curves[i];
			break;
		}
	}
	if (ci == NULL) {
		jwt_write_error(item, "Unknown EC curve: %s", raw->curve);
		return -1;
	}

	mbedtls_pk_init(&pk);

	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) {
		jwt_write_error(item, "Error setting up EC pk context");
		goto cleanup;
	}

	ec = mbedtls_pk_ec(pk);

	/* Load curve group */
	if (mbedtls_ecp_group_load(&ECDSA_RS_GRP(*ec), ci->grp_id)) {
		jwt_write_error(item, "Error loading EC group");
		goto cleanup;
	}

	/* Build uncompressed point: 0x04 || x_padded || y_padded */
	pt_len = 1 + ci->coord_len * 2;
	pt_buf = jwt_malloc(pt_len);
	if (pt_buf == NULL)
		goto cleanup;

	memset(pt_buf, 0, pt_len);
	pt_buf[0] = 0x04;

	/* Copy x, right-aligned (zero-padded on left) */
	if ((size_t)raw->x.len > ci->coord_len) {
		jwt_write_error(item,
			"EC x coordinate too long for curve");
		goto cleanup;
	}
	memcpy(pt_buf + 1 + (ci->coord_len - raw->x.len),
	       raw->x.bin, raw->x.len);

	/* Copy y, right-aligned */
	if ((size_t)raw->y.len > ci->coord_len) {
		jwt_write_error(item,
			"EC y coordinate too long for curve");
		goto cleanup;
	}
	memcpy(pt_buf + 1 + ci->coord_len +
	       (ci->coord_len - raw->y.len),
	       raw->y.bin, raw->y.len);

	/* Read the public point */
	if (mbedtls_ecp_point_read_binary(&ECDSA_RS_GRP(*ec),
					   &ECDSA_RS_Q(*ec),
					   pt_buf, pt_len)) {
		jwt_write_error(item,
				"Error generating pub key from components");
		goto cleanup;
	}

	/* Validate the public key point */
	if (mbedtls_ecp_check_pubkey(&ECDSA_RS_GRP(*ec), &ECDSA_RS_Q(*ec))) {
		jwt_write_error(item,
				"Error generating pub key from components");
		goto cleanup;
	}

	/* Private key */
	if (raw->is_private) {
		if (mbedtls_mpi_read_binary(&ECDSA_RS_D(*ec),
					     raw->d.bin, raw->d.len)) {
			jwt_write_error(item,
					"Error decoding EC private component");
			goto cleanup;
		}
	}

	ret = pk_to_pem(&pk, item, raw->is_private);

cleanup:
	jwt_freemem(pt_buf);
	if (ret != 0)
		mbedtls_pk_free(&pk);

	return ret;
}

JWT_NO_EXPORT
int mbedtls_process_eddsa(jwk_item_t *item, const jwk_eddsa_raw_t *raw)
{
	(void)raw;
	jwt_write_error(item, "MBedTLS does not support EdDSA JWK");
	return -1;
}

JWT_NO_EXPORT
void mbedtls_process_item_free(jwk_item_t *item)
{
	if (item == NULL || item->provider != JWT_CRYPTO_OPS_MBEDTLS)
		return;

	if (item->provider_data) {
		mbedtls_pk_free(item->provider_data);
		jwt_freemem(item->provider_data);
	}

	/* Scrub PEM before freeing — may contain private key material */
	if (item->pem)
		memset(item->pem, 0, strlen(item->pem));
	jwt_freemem(item->pem);

	item->pem = NULL;
	item->provider_data = NULL;
	item->provider = JWT_CRYPTO_OPS_NONE;
}
