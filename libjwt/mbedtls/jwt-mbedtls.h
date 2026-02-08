/* Copyright (C) 2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JWT_MBEDTLS_H
#define JWT_MBEDTLS_H

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER < 0x03000000
#define ECDSA_RS_GRP(ctx)    ((ctx).grp)
#define ECDSA_RS_D(ctx)      ((ctx).d)
#define ECDSA_RS_Q(ctx)      ((ctx).Q)
#define RSA_CONTEXT_LEN(ctx) ((ctx)->len)
#else
#define ECDSA_RS_GRP(ctx)    ((ctx).private_grp)
#define ECDSA_RS_D(ctx)      ((ctx).private_d)
#define ECDSA_RS_Q(ctx)      ((ctx).private_Q)
#define RSA_CONTEXT_LEN(ctx) ((ctx)->private_len)
#endif

int mbedtls_process_eddsa(jwk_item_t *item, const jwk_eddsa_raw_t *raw);
int mbedtls_process_rsa(jwk_item_t *item, const jwk_rsa_raw_t *raw);
int mbedtls_process_ec(jwk_item_t *item, const jwk_ec_raw_t *raw);
void mbedtls_process_item_free(jwk_item_t *item);

#endif /* JWT_MBEDTLS_H */
