
/* data structures */

typedef struct
{
    ASN1_OCTET_STRING *                 group_name;
    ASN1_BOOLEAN *                      attached_group;
} PROXYGROUP;


/* functions */

ASN1_METHOD * PROXYGROUP_asn1_method();

PROXYGROUP * PROXYGROUP_new();

void PROXYGROUP_free();

PROXYGROUP * PROXYGROUP_dup(
    PROXYGROUP *                        group);

PROXYGROUP * PROXYGROUP_cmp(
    const PROXYGROUP *                  a,
    const PROXYGROUP *                  b);

int PROXYGROUP_print(
    PROXYGROUP *                        group);

int PROXYGROUP_print_fp(
    FILE *                              fp,
    PROXYGROUP *                        group);

int PROXYGROUP_set_name(
    PROXYGROUP *                        group,
    char *                              group_name);

char * PROXYGROUP_get_name(
    PROXYGROUP *                        group);

int PROXYGROUP_set_attached(
    PROXYGROUP *                        group,
    int                                 attached);

int PROXYGROUP_get_attached(
    PROXYGROUP *                        group);

int i2d_PROXYGROUP(
    PROXYGROUP *                        group,
    unsigned char **                    buffer);

PROXYGROUP * d2i_PROXYGROUP(
    PROXYGROUP **                       group,
    unsigned char **                    buffer,
    long                                length);

