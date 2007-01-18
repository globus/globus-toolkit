dnl
dnl ac_crypto.m4
dnl
dnl
dnl Set up crypto library options 
dnl
dnl


dnl LAC_CRYPTO_ARGS()

AC_DEFUN([LAC_CRYPTO_ARGS],
[
])

dnl LAC_CRYPTO()

AC_DEFUN([LAC_CRYPTO],
[
    AC_REQUIRE([AC_CANONICAL_HOST])
    AC_REQUIRE([LAC_CPU])
    AC_REQUIRE([AC_PROG_CC])
    LAC_CRYPTO_ARGS
    LAC_CRYPTO_SET

    LAC_SUBSTITUTE_VAR(DATE)
    LAC_DEFINE_VAR(OPENSSLDIR)
    LAC_DEFINE_VAR(SIXTY_FOUR_BIT_LONG)
    LAC_DEFINE_VAR(SIXTY_FOUR_BIT)
    LAC_DEFINE_VAR(THIRTY_TWO_BIT)
    LAC_DEFINE_VAR(DES_PTR)
    LAC_DEFINE_VAR(DES_RISC1)
    LAC_DEFINE_VAR(DES_RISC2)
    LAC_DEFINE_VAR(DES_UNROLL)
    LAC_DEFINE_VAR(DES_LONG)
    LAC_DEFINE_VAR(BN_LLONG)
    LAC_DEFINE_VAR(BN_DIV2W)
    LAC_DEFINE_VAR(BN_DIV3W)
    LAC_DEFINE_VAR(BF_PTR)
    LAC_DEFINE_VAR(BF_PTR2)
    LAC_DEFINE_VAR(RC4_CHUNK)
    LAC_DEFINE_VAR(RC4_INDEX)
    LAC_DEFINE_VAR(RC4_INT)
    LAC_DEFINE_VAR(RC2_INT)
    LAC_DEFINE_VAR(MD2_INT)
    LAC_DEFINE_VAR(IDEA_INT)
])


dnl LAC_CRYPTO_SET
AC_DEFUN([LAC_CRYPTO_SET],
[
    # defaults:

    lac_OPENSSLDIR="\"$GLOBUS_LOCATION\""
    lac_DATE="`date`"
    lac_SIXTY_FOUR_BIT_LONG=""
    lac_SIXTY_FOUR_BIT=""
    lac_THIRTY_TWO_BIT="1"
    lac_DES_PTR=""
    lac_DES_RISC1=""
    lac_DES_RISC2=""
    lac_DES_UNROLL=""
    lac_DES_LONG="unsigned long"
    lac_BN_LLONG=""
    lac_BN_DIV2W=""
    lac_BN_DIV3W=""
    lac_BF_PTR=""
    lac_BF_PTR2=""
    lac_RC4_CHUNK=""
    lac_RC4_INDEX=""
    lac_RC4_INT="unsigned int"
    lac_RC2_INT="unsigned int"
    lac_MD2_INT="unsigned int"
    lac_IDEA_INT="unsigned int"

    case ${host} in
        *solaris*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    lac_BN_LLONG="1"
                    lac_BN_DIV2W="1"
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long"
                    lac_DES_UNROLL="1" 
                    lac_BF_PTR="1"

                    if test ! "$GCC" = "yes"; then
                        lac_DES_PTR="1"
                        lac_DES_RISC1="1"
                    fi
                ;;
                *sun4u*)
                    lac_RC4_INT="unsigned char"
                    lac_DES_UNROLL="1" 
                    lac_BF_PTR="1"

                    if test "$GCC" = "yes"; then
                        lac_RC4_CHUNK="unsigned long"
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_SIXTY_FOUR_BIT_LONG="1"
                                lac_THIRTY_TWO_BIT=""
                                lac_DES_LONG="unsigned int"
                            ;;
                            *32* )
                                lac_BN_LLONG="1"
                                lac_BN_DIV2W="1"
                            ;;
                        esac
                    else
                        # vendorcc flavor
                        lac_DES_PTR="1"
                        lac_DES_RISC1="1"
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_SIXTY_FOUR_BIT_LONG="1"
                                lac_THIRTY_TWO_BIT=""
                                lac_RC4_CHUNK="unsigned long"
                                lac_DES_LONG="unsigned int"
                            ;;
                            *32* )
                                lac_BN_LLONG="1"
                                lac_BN_DIV2W="1"
                                lac_RC4_CHUNK="unsigned long long"
                            ;;
                        esac
                    fi
                ;;
                *x86*)
                    lac_BN_LLONG="1"
                    lac_DES_PTR="1"
                    lac_DES_UNROLL="1" 

                    if test "$GCC" = "yes"; then
                        lac_RC4_INDEX="1"
                        lac_DES_RISC1="1"
                    else
                        lac_RC4_INT="unsigned char"
                        lac_RC4_CHUNK="unsigned long"
                        lac_BF_PTR="1"
                    fi
                ;;
            esac
        ;;   
        *linux*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    # gcc
                    lac_BN_LLONG="1"
                    lac_BN_DIV2W="1"
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long"
                    lac_DES_UNROLL="1" 
                    lac_BF_PTR="1"
                ;;
                *sun4u*)
                    # gcc
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long"
                    lac_DES_UNROLL="1" 
                    lac_BF_PTR="1"

                    case ${GLOBUS_FLAVOR_NAME} in
                        *64* )
                            lac_SIXTY_FOUR_BIT_LONG="1"
                            lac_THIRTY_TWO_BIT=""
                            lac_DES_LONG="unsigned int"
                        ;;
                        *32* )
                            lac_BN_LLONG="1"
                            lac_BN_DIV2W="1"
                        ;;
                    esac
                ;;
                *x86_64*)
                    # gcc
                    case ${GLOBUS_FLAVOR_NAME} in
                        *64* )
                            lac_SIXTY_FOUR_BIT_LONG="1"
                            lac_THIRTY_TWO_BIT=""
                            lac_RC4_INT="unsigned char"
                            lac_RC4_CHUNK="unsigned long"
                            lac_BF_PTR2="1"
                            lac_DES_UNROLL="1"
                            lac_DES_LONG="unsigned int"
                        ;;
                        *32* )
                            lac_BN_LLONG="1"
                            lac_DES_PTR="1"
                            lac_DES_RISC1="1"
                            lac_DES_UNROLL="1"
                            lac_RC4_INDEX="1"
                        ;;
                    esac
                ;;
                *x86*)
                    # gcc
                    lac_BN_LLONG="1"
                    lac_DES_PTR="1"
                    lac_DES_RISC1="1"
                    lac_DES_UNROLL="1"
                    lac_RC4_INDEX="1"
                ;;
                *ia64*)
                    # gcc
                    lac_SIXTY_FOUR_BIT_LONG="1"
                    lac_THIRTY_TWO_BIT=""
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long"
                ;;
                *alpha*)
                    lac_SIXTY_FOUR_BIT_LONG="1"
                    lac_THIRTY_TWO_BIT=""
                    lac_RC4_CHUNK="unsigned long"
                    lac_DES_RISC1="1" 
                    lac_DES_UNROLL="1" 

                    if test ! "$GCC" = "yes"; then
                        lac_RC4_INT="unsigned char"
                    fi
                ;;
            esac
        ;;
        *irix6*)
            case ${GLOBUS_FLAVOR_NAME} in
                *64* )
                    # gcc and vendor
                    lac_BN_DIV3W="1"
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long"
                    lac_DES_RISC2="1"
                    lac_DES_UNROLL="1"
                    lac_SIXTY_FOUR_BIT_LONG="1"
                    lac_THIRTY_TWO_BIT=""
                ;;
                *32* )
                    lac_BN_DIV3W="1"
                    lac_SIXTY_FOUR_BIT="1"
                    lac_THIRTY_TWO_BIT=""
                    lac_RC4_INT="unsigned char"
                    lac_RC4_CHUNK="unsigned long long"
                    lac_DES_RISC2="1"
                    lac_DES_PTR="1"
                    lac_DES_UNROLL="1"
                    lac_BF_PTR="1"

                    if test "$GCC" = "yes"; then
                        lac_MD2_INT="unsigned char"
                        lac_RC4_INDEX="1"
                    fi
                ;;
            esac
        ;;
        *hpux*)
            lac_DES_UNROLL="1"
            lac_DES_RISC1="1"
            lac_BN_DIV2W="1"            

            if test "$GCC" = "yes"; then
                lac_BN_LLONG="1"
                lac_DES_PTR="1"
            else
                lac_MD2_INT="unsigned char"
                lac_RC4_INDEX="1"
                lac_RC4_INT="unsigned char"
                lac_DES_LONG="unsigned int"
            fi
        ;;
        *-ibm-aix*)
            # gcc and vendor
            lac_RC4_INT="unsigned char"
            case ${GLOBUS_FLAVOR_NAME} in
                *64* )
                    lac_SIXTY_FOUR_BIT_LONG="1"
                    lac_THIRTY_TWO_BIT=""
                ;;
                *32* )
                    lac_BN_LLONG="1"
                ;;
            esac
        ;;
        *-dec-osf*)
            if test "$GCC" = "yes"; then
                lac_SIXTY_FOUR_BIT_LONG="1"
                lac_THIRTY_TWO_BIT=""
                lac_RC4_CHUNK="unsigned long"
                lac_DES_UNROLL="1"
                lac_DES_RISC1="1"
            else
                lac_SIXTY_FOUR_BIT_LONG="1"
                lac_THIRTY_TWO_BIT=""
                lac_RC4_CHUNK="unsigned long"
            fi
        ;;
        i*86*darwin*)
            lac_RC4_INT="unsigned char"
	    lac_RC4_CHUNK="unsigned long"
            lac_DES_UNROLL="1"
            lac_BF_PTR="1"
            case ${GLOBUS_FLAVOR_NAME} in
                *64* )
                    lac_SIXTY_FOUR_BIT_LONG="1"
                    lac_THIRTY_TWO_BIT=""
                ;;
                *32* )
                    lac_BN_LLONG="1"
                ;;
            esac
        ;;
        *-darwin*)
            # gcc
            lac_BN_LLONG="1"
            lac_RC4_INT="unsigned char"
	    lac_RC4_CHUNK="unsigned long"
            lac_DES_UNROLL="1"
            lac_BF_PTR="1"
        ;;
    esac
])










