/* Copyright (C) 2026 Ramin Seyed Moussavi, Yacoub Automation GmbH <ramin.moussavi@yacoub.de>
   This file is part of the JWT C Library

   SPDX-License-Identifier:  MPL-2.0
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* AFL++ persistent-mode harness for JWT token verification.
 * Build with afl-clang-fast, run with afl-fuzz. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jwt.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
	jwk_set_t *jwk_set;
	const jwk_item_t *item;
	jwt_checker_t *checker;
	int ret;

	(void)argc;
	(void)argv;

	jwk_set = jwks_create_fromfile(KEYDIR "/oct_key_256.json");
	if (!jwk_set || jwks_error(jwk_set)) {
		fprintf(stderr, "FATAL: cannot load HMAC key\n");
		return 1;
	}

	item = jwks_item_get(jwk_set, 0);
	if (!item) {
		fprintf(stderr, "FATAL: empty JWKS\n");
		return 1;
	}

	checker = jwt_checker_new();
	if (!checker) {
		fprintf(stderr, "FATAL: jwt_checker_new failed\n");
		return 1;
	}

	ret = jwt_checker_setkey(checker, JWT_ALG_HS256, item);
	if (ret) {
		fprintf(stderr, "FATAL: jwt_checker_setkey failed: %d\n", ret);
		return 1;
	}

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(10000)) {
		unsigned int len = __AFL_FUZZ_TESTCASE_LEN;

		char *str = malloc(len + 1);
		if (!str)
			continue;

		memcpy(str, buf, len);
		str[len] = '\0';

		jwt_checker_verify(checker, str);
		jwt_checker_error_clear(checker);

		free(str);
	}

	jwt_checker_free(checker);
	jwks_free(jwk_set);
	return 0;
}
