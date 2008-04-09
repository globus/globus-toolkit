#ifndef CIPHER_CTR_H
#define CIPHER_CTR_H 1

#include "openssl/aes.h"

typedef int (*aes_get_hw_aes_callback_t)(void);

void
aes_set_hw_callback(aes_get_hw_aes_callback_t func);

struct ssh_aes_ctr_ctx
{
    AES_KEY         aes_ctx;
    u_char          aes_counter[AES_BLOCK_SIZE];

    u_char          key[AES_BLOCK_SIZE];
    int             use_hw_crypto;
    int             debug;
};

#endif /* CIPHER_CTR_H */
