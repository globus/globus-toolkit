#include "globus_grim_devel.h"

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_grim_assertion_t                 assertion;
    char *                                  in_subject = "/DN test, nonesense";
    char *                                  in_username = "bresnaha";
    char *                                  out_username;
    char *                                  out_subject;
    globus_result_t                         res;
    char *                                  in_pt_array[] = {"port type 1",
                                                             "2 pt",
                                                             "third pt",
                                                             NULL};
    char *                                  in_dn_array[] = {"dn 1", "dn 2",
                                                             "dn3", NULL};
    char *                                  serialized_assertion;
    char *                                  serialized_assertion2;

    globus_module_activate(GLOBUS_GRIM_DEVEL_MODULE);

    res = globus_grim_assertion_init(
            &assertion,
            in_subject,
            in_username);
    assert(res == GLOBUS_SUCCESS);
    res = globus_grim_assertion_set_port_types_array(
            assertion,
            in_pt_array);
    assert(res == GLOBUS_SUCCESS);
    res = globus_grim_assertion_set_dn_array(
            assertion,
            in_dn_array);
    assert(res == GLOBUS_SUCCESS);

    res = globus_grim_assertion_serialize(
            assertion,
            &serialized_assertion);
    assert(res == GLOBUS_SUCCESS);

    res = globus_grim_assertion_destroy(assertion);
    assert(res == GLOBUS_SUCCESS);


    res = globus_grim_assertion_init_from_buffer(
            &assertion,
            serialized_assertion);
    assert(res == GLOBUS_SUCCESS);

    res = globus_grim_assertion_get_subject(
            assertion,
            &out_subject);
    assert(res == GLOBUS_SUCCESS);

    res = globus_grim_assertion_get_username(
            assertion,
            &out_username);
    assert(res == GLOBUS_SUCCESS);

    /* test values */
    if(strcmp(out_subject, in_subject) != 0)
    {
        fprintf(stderr, "subjects not the same: %s != %s.\n",
            out_subject, in_subject);
        assert(0);
    }

    if(strcmp(out_username, in_username) != 0)
    {
        fprintf(stderr, "usernames are not the same: %s != %s.\n",
            out_username, in_username);
        assert(0);
    }

    res = globus_grim_assertion_serialize(
            assertion,
            &serialized_assertion2);
    assert(res == GLOBUS_SUCCESS);

    res = globus_grim_assertion_destroy(assertion);
    assert(res == GLOBUS_SUCCESS);

    /*
     *  this is a lazy man's test.  it could fail and things could still
     *  be ok, since xml may be equal even if strings are not.
     */
    if(strcmp(serialized_assertion2, serialized_assertion) != 0)
    {
        fprintf(stderr, "assertions did not come out the same.\n");
        fprintf(stderr, "------------ FIRST -------------------\n");
        fprintf(stderr, serialized_assertion);
        fprintf(stderr, "------------ LAST -------------------\n");
        fprintf(stderr, serialized_assertion2);
        fprintf(stderr, "------------ END -------------------\n");
        assert(0);
    }

    /* free */
    globus_module_deactivate(GLOBUS_GRIM_DEVEL_MODULE);
    free(serialized_assertion2);
    free(serialized_assertion);

    return 0;
}
