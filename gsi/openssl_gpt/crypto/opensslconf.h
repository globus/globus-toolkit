/* crypto/opensslconf.h.  Generated automatically by configure.  */

/* use unistd by default, this test should be done by AC_CHECK_HEADERS */

#ifndef  OPENSSL_UNISTD
#   define OPENSSL_UNISTD <unistd.h>
#endif

#ifdef HEADER_BN_H
#   ifndef SIXTY_FOUR_BIT_LONG
/* #       undef SIXTY_FOUR_BIT_LONG */
#   endif
#   ifndef SIXTY_FOUR_BIT
/* #       undef SIXTY_FOUR_BIT */
#   endif
#   ifndef THIRTY_TWO_BIT
#       define THIRTY_TWO_BIT 1
#   endif
#   ifndef BN_LLONG
#       define BN_LLONG 1
#   endif
#endif

#ifdef HEADER_DES_LOCL_H
#   ifndef DES_PTR
/* #       undef DES_PTR */
#   endif 
#   ifndef DES_RISC1 
/* #       undef DES_RISC1 */
#   endif
#   ifndef DES_RISC2
/* #       undef DES_RISC2 */
#   endif
#   ifndef DES_UNROLL
#       define DES_UNROLL 1
#   endif
#   ifndef DES_LONG
#       define DES_LONG unsigned long
#   endif
#endif

#ifdef HEADER_BF_LOCL_H
#   ifndef BF_PTR
#       define BF_PTR 1
#   endif
#endif

#ifdef HEADER_RC4_H
#   ifndef RC4_CHUNK
#       define RC4_CHUNK unsigned long
#   endif
#   ifndef RC4_INT
#       define RC4_INT unsigned char
#   endif
#endif

#ifdef HEADER_RC4_LOCL_H
#   ifndef RC4_INDEX
/* #       undef RC4_INDEX */
#   endif
#endif

#ifdef HEADER_RC2_H
#   ifndef RC2_INT
#       define RC2_INT unsigned int
#   endif
#endif

#ifdef HEADER_MD2_H
#   ifndef MD2_INT
#       define MD2_INT unsigned int
#   endif
#endif


#ifdef HEADER_IDEA_H
#   ifndef IDEA_INT
#       define IDEA_INT unsigned int
#   endif
#endif

#ifdef OPENSSL_THREAD_DEFINES
#   ifndef THREADS
/* #       undef THREADS */
#   endif
#endif

#ifdef OPENSSL_OTHER_DEFINES
#   ifndef DSO_DLFCN
#       define DSO_DLFCN 1
#   endif
#   ifndef HAVE_DLFCN_H
#       define HAVE_DLFCN_H 1
#   endif
#endif
