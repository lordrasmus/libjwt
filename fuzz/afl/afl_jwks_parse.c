/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* AFL++ persistent-mode harness for JWK/JWKS JSON parsing.
 * Build with afl-clang-fast, run with afl-fuzz. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jwt.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(10000)) {
		unsigned int len = __AFL_FUZZ_TESTCASE_LEN;

		char *str = malloc(len + 1);
		if (!str)
			continue;

		memcpy(str, buf, len);
		str[len] = '\0';

		jwk_set_t *jwk_set = jwks_create(str);
		free(str);

		if (!jwk_set)
			continue;

		for (size_t i = 0; ; i++) {
			const jwk_item_t *item = jwks_item_get(jwk_set, i);
			if (!item)
				break;

			(void)jwks_item_alg(item);
			(void)jwks_item_kty(item);
			(void)jwks_item_pem(item);
			(void)jwks_item_error(item);
		}

		jwks_free(jwk_set);
	}

	return 0;
}
