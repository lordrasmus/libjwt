/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Fuzz JWT token verification with a fixed HMAC key.
 * Build with: -fsanitize=fuzzer,address,undefined
 * Run:   ./fuzz_jwt_verify fuzz/corpus_jwt/ -max_total_time=60 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jwt.h>

static jwt_checker_t *g_checker;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	jwk_set_t *jwk_set;
	const jwk_item_t *item;
	int ret;

	(void)argc;
	(void)argv;

	jwk_set = jwks_create_fromfile(KEYDIR "/oct_key_256.json");
	if (!jwk_set || jwks_error(jwk_set)) {
		fprintf(stderr, "FATAL: cannot load HMAC key\n");
		abort();
	}

	item = jwks_item_get(jwk_set, 0);
	if (!item) {
		fprintf(stderr, "FATAL: empty JWKS\n");
		abort();
	}

	g_checker = jwt_checker_new();
	if (!g_checker) {
		fprintf(stderr, "FATAL: jwt_checker_new failed\n");
		abort();
	}

	ret = jwt_checker_setkey(g_checker, JWT_ALG_HS256, item);
	if (ret) {
		fprintf(stderr, "FATAL: jwt_checker_setkey failed: %d\n", ret);
		abort();
	}

	/* jwk_set must stay alive — the checker references the key */
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* jwt_checker_verify needs a null-terminated string */
	char *buf = malloc(size + 1);
	if (!buf)
		return 0;

	memcpy(buf, data, size);
	buf[size] = '\0';

	jwt_checker_verify(g_checker, buf);
	jwt_checker_error_clear(g_checker);

	free(buf);
	return 0;
}
