#include "GridFTPRegistryService_client.h"
#include "ContentType.h"
#include "wssg_EntryType.h"
#include "globus_wsrf_core_tools.h"

#define ELEMENT_NAME  "GridFTPRegistryService"


static char *                           reg_l_out_epr_file = NULL;
static char *                           reg_l_in_epr_file = NULL;
static char *                           reg_l_contact_string = NULL;
static int                              reg_l_termination_time = 60*10;
static int                              reg_l_connection_count = -1;
static globus_bool_t                    reg_l_list = GLOBUS_FALSE;

static
globus_result_t
reg_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "reg_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        parm));
}

static
globus_result_t
reg_l_opts_list(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    reg_l_list = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
reg_l_opts_cs(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    reg_l_contact_string = opt;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
reg_l_opts_out_epr(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    reg_l_out_epr_file = opt;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
reg_l_opts_in_epr(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    reg_l_in_epr_file = opt;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
reg_l_opts_current_connections(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 tmp_i;

    sc = sscanf(opt, "%d", &tmp_i);
    if(sc != 1)
    {
        *out_parms_used = 0;
        return globus_error_put(globus_error_construct_error(
            NULL,
            NULL,
            2,
            __FILE__,
            "reg_l_opts_unknown",
            __LINE__,
            "connection count must be an integer: %s",
            opt));
    }
    reg_l_connection_count = tmp_i;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
reg_l_opts_termination_time(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 tmp_i;

    sc = sscanf(opt, "%d", &tmp_i);
    if(sc != 1)
    {
        *out_parms_used = 0;
        return globus_error_put(globus_error_construct_error(
            NULL,
            NULL,
            2,
            __FILE__,
            "reg_l_opts_unknown",
            __LINE__,
            "termination time must be an integer: %s",
            opt));
    }
    reg_l_termination_time = tmp_i;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}


globus_options_entry_t                   reg_l_opts_table[] =
{
    {"contact-string", "cs", NULL, "<contact string>",
        "sets the contact string at which the gridftp server is available.  "
        "Implies the creation of a new entry.",
        1, reg_l_opts_cs},
    {"out-epr-file", "o", NULL, "<filename>",
        "sets the location to which the epr of the newly created entry "
        "will be written.",
        1, reg_l_opts_out_epr},
    {"in-epr-file", "i", NULL, "<filename>",
        "The location of the epr file to read in.  If creating a new entry "
        "it is the epr of the registry.  If updating an entry it is the "
        "epr of that entry.",
        1, reg_l_opts_in_epr},
    {"termination-time", "t", NULL, "<seconds>",
        "The number of seconds that the entry will live.",
        1, reg_l_opts_termination_time},
    {"list", "l", NULL, "",
        "list the currently registered contact strings.",
        0, reg_l_opts_list},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

void
reg_test_result(
    globus_result_t                     result)
{
    if(result != GLOBUS_SUCCESS)
    {
        printf("%s\n", globus_error_print_friendly(globus_error_get(result)));
        exit(1);
    }
}

static
void
reg_write_epr(
    wsa_EndpointReferenceType *         epr,
    const char *                        epr_filename)
{
    globus_result_t                     result;
    globus_soap_message_handle_t        soap_handle;
    xsd_QName                           element_name;

    element_name.Namespace = ELEMENT_NAME;
    element_name.local = ELEMENT_NAME;

    result = globus_soap_message_handle_init_to_file(
        &soap_handle,
        epr_filename,
        GLOBUS_XIO_FILE_CREAT | GLOBUS_XIO_FILE_TRUNC);
    reg_test_result(result);

    result = wsa_EndpointReferenceType_serialize(
        &element_name,
        epr,
        soap_handle,
        0);
    reg_test_result(result);

    globus_soap_message_handle_destroy(soap_handle);
}

static
void
reg_l_parse_opts(
    int                                 argc,
    char **                             argv)
{
    globus_result_t                     result;
    globus_options_handle_t             opt_h;

    globus_options_init(&opt_h, reg_l_opts_unknown, NULL, reg_l_opts_table);
    result = globus_options_command_line_process(opt_h, argc, argv);
    reg_test_result(result);

    if(reg_l_in_epr_file == NULL)
    {
        fprintf(stderr, "You must provide an input EPR filename.  "
                "--help for more information.\n");
        exit(1);
    }
}

static
void
reg_l_list_cs(
    wsa_EndpointReferenceType *         epr)
{
    wssg_EntryType *                    et;
    globus_result_t                     result;
    int                                 i;
    GridFTPRegistryService_client_handle_t
                                        client_handle;
    wsrp_GetResourcePropertyResponseType *
                                        response;
    int                                 fault_type;
    xsd_any *                           fault;
    ContentType *                       content;

    result = GridFTPRegistryService_client_init(&client_handle, NULL, NULL);
    reg_test_result(result);

    result = GridFTPRegistryPortType_GetResourceProperty_epr(
        client_handle,
        epr,
        &GridFTPRegistryPortType_Entry_rp_qname,
        &response,
        (GridFTPRegistryPortType_GetResourceProperty_fault_t*)&fault_type,
         &fault);
    reg_test_result(result);

    printf("Currently registered contact strings\n");
    for(i = 0; i < response->any.length; i++)
    {
        et = (wssg_EntryType *)response->any.elements[i].value;

        content = (ContentType *)et->Content->value;
        printf("--> %s : %d\n", content->ContactString, content->CurrentTransfers);
    }
}

int
main(
    int                                 argc,
    char *                              argv[])
{
    time_t                              tm;
    struct tm *                         tm_now;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GridFTPRegistryService_client_handle_t
                                        client_handle;
    globus_soap_message_handle_t        soap_handle;
    int                                 fault_type;
    xsd_any *                           fault;
    xsd_QName                           element_name;
    wsa_EndpointReferenceType *         epr;
    wssg_AddType                        add;
    wsa_EndpointReferenceType *         response = NULL;
    ContentType                         content;

    globus_module_activate(GLOBUS_SOAP_MESSAGE_MODULE);
    globus_module_activate(GRIDFTPREGISTRYSERVICE_MODULE);

    reg_l_parse_opts(argc, argv);

    element_name.Namespace = ELEMENT_NAME;
    element_name.local = ELEMENT_NAME;

    /* load the epr from the file */
    result = globus_soap_message_handle_init_from_file(
        &soap_handle,
        reg_l_in_epr_file);
    reg_test_result(result);

    result = wsa_EndpointReferenceType_init(&epr);
    reg_test_result(result);

    result = wsa_EndpointReferenceType_deserialize(
        &element_name,
        epr,
        soap_handle,
        0);
    reg_test_result(result);
    globus_soap_message_handle_destroy(soap_handle);

    /* */
    result = GridFTPRegistryService_client_init(&client_handle, NULL, NULL);
    reg_test_result(result);

    tm = time(NULL) + reg_l_termination_time;
    tm_now = gmtime(&tm);

    if(reg_l_contact_string != NULL)
    {
        wssg_AddType_init_contents(&add);
        /* initialize what we are adding */
        ContentType_init_contents(&content);
        xsd_string_init_contents_cstr(
            &content.ContactString, reg_l_contact_string);

        add.Content.any_info = &ContentType_info;
        add.Content.value = &content;
        add.MemberEPR = *epr; /* anything for now */
        /* set time */
        xsd_dateTime_init(&add.InitialTerminationTime);
        memcpy(add.InitialTerminationTime, tm_now, sizeof(struct tm));

       result = GridFTPRegistryPortType_Add_epr(
            client_handle,
            epr,
            &add,
            &response,
            (GridFTPRegistryPortType_Add_fault_t *)&fault_type,
            &fault);
        reg_test_result(result);

        /* if the user wants to save the new epr, write it out */
        if(reg_l_out_epr_file != NULL)
        {
            reg_write_epr(response, reg_l_out_epr_file);
        }
    }
    else /* we are updating an existing one */
    {
/*        result = wsrl_SetTerminationTimeType_init_contents(&termTime);
        reg_test_result(result);

        memcpy(&termTime.RequestedTerminationTime, tm_now, sizeof(struct tm));
*/
    }

    if(reg_l_list)
    {
        reg_l_list_cs(epr);
    }

    globus_module_deactivate(GRIDFTPREGISTRYSERVICE_MODULE);

    return 0;
}
