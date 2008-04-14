/* $OpenBSD: cipher-ctr.c,v 1.10 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>

#include "cipher-ctr.h"

const EVP_CIPHER *evp_aes_128_ctr(void);
void ssh_aes_ctr_iv(EVP_CIPHER_CTX *, int, u_char *, u_int);
static aes_get_hw_aes_callback_t aes_get_hw_callback = NULL;

void
aes_set_hw_callback(aes_get_hw_aes_callback_t func)
{
    aes_get_hw_callback = func;
}

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
static void
ssh_ctr_inc(u_char *ctr, u_int len)
{
	int i;

	for (i = len - 1; i >= 0; i--)
		if (++ctr[i])	/* continue on overflow */
			return;
}

static int
ssh_aes_ctr(EVP_CIPHER_CTX *ctx, u_char *dest, const u_char *src,
    u_int len)
{
	struct ssh_aes_ctr_ctx *c;
	u_int n = 0;
	u_char buf[AES_BLOCK_SIZE];

        /*fprintf(stderr, "ssh_aes_ctr enter: %p\n", ctx);*/
	if (len == 0)
		return (1);
	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL)
		return (0);

        if (!c->use_hw_crypto)
        {
            if (c->debug)
            {
                int i;
                fprintf(stderr,
                        "ssh_aes_ctr software crypto:\nCrypting with key:\n    ");
                for (i = 0; i < AES_BLOCK_SIZE; i++) {
                        fprintf(stderr, "0x%02x%s", c->key[i], i == 7 ? "\n    " : " ");
                }
                fprintf(stderr, "\n");
            }
            while ((len--) > 0) {
                    if (n == 0) {
                            AES_encrypt(c->aes_counter, buf, &c->aes_ctx);
                            ssh_ctr_inc(c->aes_counter, AES_BLOCK_SIZE);
                            if (c->debug) {
                                    int i;
                                    fprintf(stderr, "Incrementing counter\n    ");

                                    for (i = 0; i < AES_BLOCK_SIZE; i++) {
                                            fprintf(stderr, "0x%02x%s",
                                                    (unsigned int) c->aes_counter[i],
                                                    i == 7 ? "\n    " : " ");
                                    }
                                    fprintf(stderr, "\n");
                            }
                    }
                    *(dest++) = *(src++) ^ buf[n];
                    n = (n + 1) % AES_BLOCK_SIZE;
            }
        }
        else
        {
            if (c->debug)
            {
                fprintf(stderr, "ssh_aes_ctr flagged crypto: [ctx = %p]\n", ctx);
            }
            memcpy(dest, src, len);
        }
	return (1);
}

static int
ssh_aes_ctr_init(EVP_CIPHER_CTX *ctx, const u_char *key, const u_char *iv,
    int enc)
{
	struct ssh_aes_ctr_ctx *c;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL) {
                /*fprintf(stderr, "ssh_aes_ctr_init: allocate data [%p]\n", ctx);*/
		c = malloc(sizeof(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	if (key != NULL)
		AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
		    &c->aes_ctx);
	if (iv != NULL)
		memcpy(c->aes_counter, iv, AES_BLOCK_SIZE);

        if (getenv("AES128_CTR_DEBUG"))
        {
            c->debug = 1;
        }
        else
        {
            c->debug = 0;
        }

        if (aes_set_hw_callback != NULL)
        {
            c->use_hw_crypto = (*aes_get_hw_callback)();
        }
        else
        {
            c->use_hw_crypto = 0;
        }

        if (c->use_hw_crypto)
        {
            memcpy(c->key, key, AES_BLOCK_SIZE);
        }

        if (c->debug)
        {
            int i;

            fprintf(stderr, "AES128CTR: Key:\n");
            for (i = 0; i < EVP_CIPHER_CTX_key_length(ctx); i++)
            {
                fprintf(stderr, "0x%02x%c", key[i], (i%8 == 7) ? '\n' : ' ');
            }

            fprintf(stderr, "AES128CTR: IV:\n");
            for (i = 0; i < EVP_CIPHER_CTX_key_length(ctx); i++)
            {
                fprintf(stderr, "0x%02x%c", iv[i], (i%8 == 7) ? '\n' : ' ');
            }
        }

	return (1);
}

static int
ssh_aes_ctr_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct ssh_aes_ctr_ctx *c;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != NULL) {
		memset(c, 0, sizeof(*c));
		free(c);
		EVP_CIPHER_CTX_set_app_data(ctx, NULL);
	}
	return (1);
}

void
ssh_aes_ctr_iv(EVP_CIPHER_CTX *evp, int doset, u_char * iv, u_int len)
{
	struct ssh_aes_ctr_ctx *c;

	if ((c = EVP_CIPHER_CTX_get_app_data(evp)) == NULL)
        {
            /*fprintf(stderr, "ssh_aes_ctr_iv: no context");*/
            abort();
        }
	if (doset)
		memcpy(c->aes_counter, iv, len);
	else
		memcpy(iv, c->aes_counter, len);
}

const EVP_CIPHER *
EVP_aes_128_ctr(void)
{
	static EVP_CIPHER aes_ctr;
        char globus_aes128_ctr_oid[] = "1.3.6.1.4.1.3536.1.2.1";
        char globus_aes128_ctr_sn[] = "aes128-ctr";
        char globus_aes128_ctr_ln[] = "aes128-ctr cipher";
        static int nid = 0;

        if (nid == 0)
        {
            nid = OBJ_create(globus_aes128_ctr_oid, globus_aes128_ctr_sn,
                            globus_aes128_ctr_ln);
        }

	memset(&aes_ctr, 0, sizeof(EVP_CIPHER));
	aes_ctr.nid = nid;
	aes_ctr.block_size = AES_BLOCK_SIZE;
	aes_ctr.iv_len = AES_BLOCK_SIZE;
	aes_ctr.key_len = 16;
	aes_ctr.init = ssh_aes_ctr_init;
	aes_ctr.cleanup = ssh_aes_ctr_cleanup;
	aes_ctr.do_cipher = ssh_aes_ctr;
	return (&aes_ctr);
}
