/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Fuzz JWK / JWKS JSON parsing and key import.
 * Build with: -fsanitize=fuzzer,address,undefined
 * Run:   ./fuzz_jwks_parse fuzz/corpus_jwks/ -max_total_time=60 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jwt.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	jwk_set_t *jwk_set;
	size_t i;

	/* jwks_create needs a null-terminated string */
	char *buf = malloc(size + 1);
	if (!buf)
		return 0;

	memcpy(buf, data, size);
	buf[size] = '\0';

	jwk_set = jwks_create(buf);
	free(buf);

	if (!jwk_set)
		return 0;

	/* Iterate items to trigger backend key parsing */
	for (i = 0; ; i++) {
		const jwk_item_t *item = jwks_item_get(jwk_set, i);
		if (!item)
			break;

		/* Touch accessors to exercise more code paths */
		(void)jwks_item_alg(item);
		(void)jwks_item_kty(item);
		(void)jwks_item_pem(item);
		(void)jwks_item_error(item);
	}

	jwks_free(jwk_set);
	return 0;
}
