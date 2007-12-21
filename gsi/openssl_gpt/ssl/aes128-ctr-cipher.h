/* ssl/aes128-ctr-cipher.h */

#ifndef HEADER_AES128_CTR_CIPHER_H 
#define HEADER_AES128_CTR_CIPHER_H 

/* Cipher IDs with 0xFF as the first byte are vendor-specific (0x2F is the
 * LSB of the TLS1_CK_RSA_WITH_AES_128_SHA)
 */
#define SSL3_CK_RSA_WITH_AES_128_CTR_SHA        0x0300FF2F
#define SSL3_TXT_RSA_WITH_AES_128_CTR_SHA       "AES128-CTR-SHA"

#endif
