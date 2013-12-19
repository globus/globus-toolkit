#include <gssapi.h>

int
nonterminated(gss_cred_id_t cred, OM_uint32 option_req)
{
    OM_uint32 major_status, minor_status;
    gss_buffer_desc token_buffer, nonterminated_token_buffer;
    gss_cred_id_t imported_cred;
    int rc = 0;

    do
    {
        major_status = gss_export_cred(
            &minor_status,
            cred,
            GSS_C_NO_OID,
            option_req,
            &token_buffer);
    }
    while (major_status == GSS_S_CONTINUE_NEEDED);

    if (major_status != GSS_S_COMPLETE)
    {
        rc = 1;

        goto failed_export;
    }

    nonterminated_token_buffer.value = malloc(token_buffer.length+1);
    if (nonterminated_token_buffer.value == NULL)
    {
        goto failed_malloc;
    }
    memcpy(
            nonterminated_token_buffer.value,
            token_buffer.value,
            token_buffer.length);
    ((char*) nonterminated_token_buffer.value)[token_buffer.length]='a';

    nonterminated_token_buffer.length = token_buffer.length;

    do
    {
        major_status = gss_import_cred(
                &minor_status,
                &imported_cred,
                0,
                option_req,
                &nonterminated_token_buffer,
                0,
                NULL);
    } while (major_status == GSS_S_CONTINUE_NEEDED);

    if (major_status != GSS_S_COMPLETE)
    {
        rc = 1;
        goto failed_import;
    }

    gss_release_cred(
            &minor_status,
            &imported_cred);

failed_import:
    free(nonterminated_token_buffer.value);
failed_malloc:
    if (option_req == 1)
    {
        char * p = memchr(token_buffer.value, '=', token_buffer.length);
        size_t pathlen;
        char * path;

        if (p != NULL)
        {
            pathlen = token_buffer.length - (p - (char*) token_buffer.value);

            path = malloc(pathlen);
            if (path)
            {
                memcpy(path, p+1, pathlen-1);
                path[pathlen-1] = '\0';
                remove(path);
                free(path);
            }
        }
    }
    gss_release_buffer(
        &minor_status,
        &token_buffer);
failed_export:
    return rc;
}

int main()
{
    gss_cred_id_t cred;
    OM_uint32 major_status, minor_status;
    int rc1, rc2;

    do
    {
        major_status = gss_acquire_cred(
            &minor_status,
            GSS_C_NO_NAME,
            0,
            GSS_C_NO_OID_SET,
            GSS_C_BOTH,
            &cred,
            NULL,
            NULL);
    } while (major_status == GSS_S_CONTINUE_NEEDED);

    printf("1..2\n");

    if (GSS_ERROR(major_status))
    {
        fprintf(stderr, "Unable to acquire credentials. No tests run\n");
        exit(EXIT_FAILURE);
    }
    rc1 = nonterminated(cred, 0);
    printf("%s - GSS_IMPEXP_OPAQUE_FORM\n", (rc1 == 0) ? "ok" : "not ok");
    rc2 = nonterminated(cred, 1);
    printf("%s - GSS_IMPEXP_MECH_SPECIFIC\n", (rc2 == 0) ? "ok" : "not ok");

    gss_release_cred(
            &minor_status,
            &cred);

    return !(rc1 == 0 && rc2 == 0);
}
