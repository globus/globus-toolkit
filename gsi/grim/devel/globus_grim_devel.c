#include "globus_gss_assist.h"
#include "globus_common.h"
#include "globus_error.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"
#include <expat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define GRIM_ASSERTION_FORMAT_VERSION "1"
#define GRIM_OID                      "1.3.6.1.4.1.3536.1.1.1.7"
#define GRIM_SN                       "GRIMPOLICY"
#define GRIM_LN                       "GRIM Policy Language"

static int globus_l_grim_devel_activate(void);
static int globus_l_grim_devel_deactivate(void);

static globus_bool_t                            globus_l_grim_activated 
                                                            = GLOBUS_FALSE;
static int                                      globus_l_grim_NID;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_grim_devel_module =
{
    "globus_grim_devel",
    globus_l_grim_devel_activate,
    globus_l_grim_devel_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static int 
globus_l_grim_devel_activate()
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_l_grim_activated = GLOBUS_TRUE;
    globus_l_grim_NID = OBJ_create(GRIM_OID, GRIM_SN, GRIM_LN);
}

static int 
globus_l_grim_devel_deactivate()
{
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_l_grim_activated = GLOBUS_FALSE;
}


/*************************************************************************
 *
 ************************************************************************/

/**
 *  
 */
globus_result_t
globus_grim_devel_get_NID(
    int *                                   nid)
{
    if(!globus_l_grim_activated)
    {
        return globus_error_put(
                   );
    }

    *nid = globus_l_grim_NID;
    
    return GLOBUS_SUCCESS;
}


globus_result_t
grim_build_assertion(
    char **                                 out_assertion_string,
    char *                                  subject,
    char *                                  username,
    char **                                 dna,
    char **                                 port_types)
{
    char *                                  buffer;
    int                                     ctr;
    int                                     buffer_size = 1024;
    int                                     buffer_ndx = 0;
    char                                    hostname[MAXHOSTNAMELEN];

    globus_libc_gethostname(hostname, MAXHOSTNAMELEN);
    buffer = globus_malloc(sizeof(char) * buffer_size);

    GrowString(buffer, buffer_size, "<GrimAssertion>\n", buffer_ndx);
    GrowString(buffer, buffer_size, "    <Version>", buffer_ndx);
    GrowString(buffer, buffer_size, GRIM_ASSERTION_FORMAT_VERSION, buffer_ndx);
    GrowString(buffer, buffer_size, "    </Version>\n", buffer_ndx);
    GrowString(buffer, buffer_size, 
        "    <ServiceGridId Format=\"#X509SubjectName\">", 
        buffer_ndx);
    GrowString(buffer, buffer_size, subject, buffer_ndx);
    GrowString(buffer, buffer_size, "</ServerGridId>\n", buffer_ndx);
    GrowString(buffer, buffer_size, 
        "    <ServiceLocalId Format=\"#UnixAccountName\" \n", 
        buffer_ndx);
    GrowString(buffer, buffer_size, "        NameQualifier=\"", buffer_ndx);
    GrowString(buffer, buffer_size, hostname, buffer_ndx);
    GrowString(buffer, buffer_size, "\">", buffer_ndx);
    GrowString(buffer, buffer_size, username, buffer_ndx);
    GrowString(buffer, buffer_size, "</ServiceLocalId>\n", buffer_ndx);

    /* add all mapped dns */
    for(ctr = 0; dna[ctr] != NULL; ctr++)
    {
        GrowString(buffer, buffer_size, 
            "<authorizedClientId Format=\"#X509SubjectName\">",
            buffer_ndx);
        GrowString(buffer, buffer_size, dna[ctr], buffer_ndx);
        GrowString(buffer, buffer_size, "</AuthorizedClientId>\n", buffer_ndx);
    }

    /* add in port_types */
    for(ctr = 0; port_types[ctr] != NULL; ctr++)
    {
        GrowString(buffer, buffer_size, "<authorizedPortType>", buffer_ndx);
        GrowString(buffer, buffer_size, port_types[ctr], buffer_ndx);
        GrowString(buffer, buffer_size, "</authorizedPortType>\n", buffer_ndx);
    }

    GrowString(buffer, buffer_size, "</GRIMAssertion>\n", buffer_ndx);

    return buffer;
}
