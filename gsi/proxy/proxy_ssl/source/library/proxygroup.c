
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>


#include "proxy_ssl_internal.h"
#include "proxygroup.h"

/**
 * @ingroup proxygroup
 *
 * Creates an ASN1_METHOD structure, which contains
 * pointers to routines that convert any PROXYGROUP
 * structure to its associated ASN.1 DER encoded form
 * and vice-versa.
 *
 * @return the ASN1_METHOD object
 */
ASN1_METHOD * PROXYGROUP_asn1_meth()
{
    static ASN1_METHOD proxygroup_asn1_meth =
    {
        (int (*)())   i2d_PROXYGROUP,
        (char *(*)()) d2i_PROXYGROUP,
        (char *(*)()) PROXYGROUP_new,
        (void (*)()) PROXYGROUP_free
    };
    return (&proxygroup_asn1_meth);
}

/**
 * @ingroup proxygroup
 *
 * Allocates and initializes a new PROXYGROUP structure.
 *
 * @return pointer to the new PROXYGROUP
 */
PROXYGROUP * PROXYGROUP_new()
{
    ASN1_CTX                            c;
    PROXYGROUP *                        ret;

    ret = NULL;

    M_ASN1_New_Malloc(ret, PROXYGROUP);
    M_ASN1_New(ret->group_name, M_ASN1_OCTET_STRING_new);
    ret->attached_group = (ASN1_BOOLEAN *)OPENSSL_malloc(sizeof(ASN1_BOOLEAN));
    *(ret->attached_group) = 0;
    return (ret);
    M_ASN1_New_Error(ASN1_F_PROXYGROUP_NEW);
}

/**
 * @ingroup proxygroup
 *
 * Frees the PROXYGROUP structure
 * 
 * @param group pointer ot the PROXYGROUP structure
 * to be freed
 */
void PROXYGROUP_free(
    PROXYGROUP *                        group)
{
    if(group == NULL) return;
    M_ASN1_OCTET_STRING_free(group->group_name);
    OPENSSL_free(group->attached_group);
    group->attached_group = NULL;
    OPENSSL_free(group);
}

/**
 * @ingroup proxygroup
 *
 * Makes a copy of the PROXYGROUP
 *
 * @param group the PROXYGROUP to be copied
 *
 * @return the new copied PROXYGROUP
 */
PROXYGROUP * PROXYGROUP_dup(
    PROXYGROUP *                        group)
{
    return ((PROXYGROUP *) ASN1_dup((int (*)())i2d_PROXYGROUP,
                                    (char *(*)())d2i_PROXYGROUP,
                                    (char *)group));
}

/**
 * @ingroup proxygroup
 *
 * Compares the two PROXYGROUP structures by
 * comparing each field in the two structures.
 * 
 * @param a the first PROXYGROUP
 * @param b the second PROXYGROUP
 *
 * @return an integer - the result of the comparison.
 * The comparison compares each of the fields, so if any
 * of those fields are equal, 0 is returned.  A nonzero value is
 * returned otherwise.
 */
int PROXYGROUP_cmp(
    const PROXYGROUP *                  a,
    const PROXYGROUP *                  b)
{
    if(ASN1_OCTET_STRING_cmp(a->group_name, b->group_name) &&
       (a->attached_group == b->attached_group))
    {
        return 1;
    }
    return 0;
}

int PROXYGROUP_print(
    BIO *                               bp,
    PROXYGROUP *                        group)
{
    int                                 ret,
                                        tmpret;

    if(ret = BIO_printf(bp, "PROXYGROUP::GroupName: ") < 0)
    {
        return ret;
    }
    if(tmpret = ASN1_STRING_print(bp, group->group_name) < 0)
    {
        return tmpret;
    }
    ret += tmpret;
    if(tmpret = BIO_printf(bp, "PROXYGROUP::AttachedGroup: %s", 
                           group->attached_group ? "TRUE" : "FALSE") < 0)
    {
        return tmpret;
    }

    return (ret + tmpret);
}

int PROXYGROUP_print_fp(
    FILE *                              fp,
    PROXYGROUP *                        group)
{
    int                                 ret;

    BIO * bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret = PROXYGROUP_print(bp, group);
    BIO_free(bp);

    return (ret);
}

int PROXYGROUP_set_name(
    PROXYGROUP *                        group,
    char *                              group_name,
    long                                length)
{
    if(group_name != NULL)
    {
        return ASN1_OCTET_STRING_set(group->group_name, group_name, length);
    }
    return 0;
}

char * PROXYGROUP_get_name(
    PROXYGROUP *                        group,
    long *                              length)
{
    *length = group->group_name->length;
    return group->group_name->data;
}

int PROXYGROUP_set_attached(
    PROXYGROUP *                        group,
    ASN1_BOOLEAN                        attached)
{
    *(group->attached_group) = attached;
    return 1;
}

ASN1_BOOLEAN * PROXYGROUP_get_attached(
    PROXYGROUP *                        group)
{
    return group->attached_group;
}

int i2d_PROXYGROUP(
    PROXYGROUP *                        group,
    unsigned char **                    buffer)
{
    unsigned char **                    pp;

    M_ASN1_I2D_vars(group);

    pp = buffer;

    M_ASN1_I2D_len(group->group_name,
                   i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_len(*(group->attached_group),
                   i2d_ASN1_BOOLEAN);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(group->group_name, i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_put(*(group->attached_group), i2d_ASN1_BOOLEAN);
    M_ASN1_I2D_finish();
}

PROXYGROUP * d2i_PROXYGROUP(
    PROXYGROUP **                       group,
    unsigned char **                    buffer,
    long                                length)
{
    unsigned char **                    pp;

    M_ASN1_D2I_vars(group, PROXYGROUP *, PROXYGROUP_new);

    pp = buffer;
    
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get(ret->group_name, d2i_ASN1_OCTET_STRING);
    
    if((c.slen != 0) && (M_ASN1_next == (V_ASN1_UNIVERSAL|V_ASN1_BOOLEAN)))
    {
        c.q = c.p;
        if(d2i_ASN1_BOOLEAN(ret->attached_group, &c.p, c.slen) < 0) goto err;
    }

    M_ASN1_D2I_Finish(group, PROXYGROUP_free, ASN1_F_D2I_PROXYGROUP);
}
