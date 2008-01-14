dnl
dnl ac_asm.m4
dnl
dnl
dnl Set up assembler options 
dnl
dnl


dnl LAC_ASM_ARGS()

AC_DEFUN([LAC_ASM_ARGS],
[
    AC_ARG_ENABLE(asm,
        [  --disable-asm                disable use of handcoded assembler],
	    [lac_asm="$enableval"],
	    [lac_asm=${lac_asm='yes'}])
])

dnl LAC_ASM()

AC_DEFUN([LAC_ASM],
[
    AC_REQUIRE([AC_CANONICAL_HOST])
    AC_REQUIRE([LAC_CPU])
    LAC_ASM_ARGS

    # disable asm if debug is turned on
    # or if flavor is mpi based

    if test "$GLOBUS_DEBUG" = "yes" || echo $GLOBUS_FLAVOR_NAME | grep mpicc 
    then
        lac_asm="no"
    fi

    LAC_ASM_SET

    LAC_SUBSTITUTE_VAR(BN_OBJ)
    LAC_SUBSTITUTE_VAR(DES_OBJ)
    LAC_SUBSTITUTE_VAR(BF_OBJ)
    LAC_SUBSTITUTE_VAR(CAST_OBJ)
    LAC_SUBSTITUTE_VAR(RC4_OBJ)
    LAC_SUBSTITUTE_VAR(RC5_OBJ)
    LAC_SUBSTITUTE_VAR(SHA1_OBJ)
    LAC_SUBSTITUTE_VAR(MD5_OBJ)
    LAC_SUBSTITUTE_VAR(RMD_OBJ)
    LAC_SUBSTITUTE_VAR(CFLAGS)
    AC_REQUIRE([LAC_PROG_AS])
])

dnl LAC_ASM_SET
AC_DEFUN([LAC_ASM_SET],
[
    lac_CFLAGS="$CFLAGS "
    lac_BN_OBJ="bn_asm.lo"
    lac_BF_OBJ="bf_enc.lo"
    lac_DES_OBJ="des_enc.lo fcrypt_b.lo"
    lac_CAST_OBJ="c_enc.lo"
    lac_RC4_OBJ="rc4_enc.lo"
    lac_RC5_OBJ="rc5_enc.lo"
    lac_SHA1_OBJ=" "
    lac_MD5_OBJ=" "
    lac_RMD_OBJ=" "

    if test "$lac_asm" = "yes"; then
        case ${host} in
            *solaris*)
                case ${lac_cv_CPU} in
                    *sun4m*|*sun4d*)
                        lac_BN_OBJ="asm/sparcv8.lo"
                    ;;
                    *sun4u*)
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_MD5_OBJ="asm/md5-sparcv8plus.lo"
                            ;;
                            *32* )
                                lac_BN_OBJ="asm/sparcv8.lo"
                            ;;
                        esac
                    ;;
                    *x86*)
#  gcc/solaris ld doesn't like the assembler stuff, so disable it for now
#
#                            lac_BN_OBJ="asm/bn86-sol.lo asm/co86-sol.lo"
#                            lac_BF_OBJ="asm/bx86-sol.lo"
#                            lac_DES_OBJ="asm/dx86-sol.lo asm/yx86-sol.lo"
#                            lac_CAST_OBJ="asm/cx86-sol.lo"
#                            lac_RC4_OBJ="asm/rx86-sol.lo"
#                            lac_RC5_OBJ="asm/r586-sol.lo"
#                            lac_SHA1_OBJ="asm/sx86-sol.lo"
#                            lac_MD5_OBJ="asm/mx86-sol.lo"
#                            lac_RMD_OBJ="asm/rm86-sol.lo"
                    ;;
                esac
            ;;   
            *linux*)
                case ${lac_cv_CPU} in
                    *sun4m*|*sun4d*)
                        lac_BN_OBJ="asm/sparcv8.lo"
                    ;;
                    *sun4u*)
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_MD5_OBJ="asm/md5-sparcv8plus.lo"
                            ;;
                            *32* )
                                lac_BN_OBJ="asm/sparcv8plus.lo"
                            ;;
                        esac
                    ;;
                    *x86_64*)
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_BN_OBJ="asm/x86_64-gcc.lo"
                            ;;
                        esac
                    ;;
                    *x86*)
                        lac_BN_OBJ="asm/bn86-elf.lo asm/co86-elf.lo"
                        lac_BF_OBJ="asm/bx86-elf.lo"
                        lac_DES_OBJ="asm/dx86-elf.lo asm/yx86-elf.lo"
                        lac_CAST_OBJ="asm/cx86-elf.lo"
                        lac_RC4_OBJ="asm/rx86-elf.lo"
                        lac_RC5_OBJ="asm/r586-elf.lo"
                        lac_SHA1_OBJ="asm/sx86-elf.lo"
                        lac_MD5_OBJ="asm/mx86-elf.lo"
                        lac_RMD_OBJ="asm/rm86-elf.lo"
                    ;;
                    *ia64*)
                        lac_BN_OBJ="asm/ia64.lo"
                    ;;
                esac
            ;;   
            *irix6*)
                case ${lac_cv_CPU} in
                    *mips3*|*mips4*)
                        dnl this needs testing
                        lac_BN_OBJ="asm/mips3.lo"
                    ;;
                esac
            ;;
        esac
    else
        lac_CFLAGS="-DOPENSSL_NO_ASM $lac_CFLAGS"
        AC_DEFINE(OPENSSL_NO_ASM)
    fi
])







