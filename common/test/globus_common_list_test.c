#include "globus_common.h"

int 
main(
    int                         argc, 
    char *                      argv[])
{
    globus_list_t *             list = GLOBUS_NULL;
    void *                      ptr;
    int                         x1 = 1;
    int                         x2 = 2;
    int                         x3 = 3;
    int                         x4 = 4;
    globus_list_t *             i;


    globus_module_activate(GLOBUS_COMMON_MODULE);

    if(globus_list_size(list) != 0)
    {
        printf("size test failed\n");
        return -1;
    }

    globus_list_insert(&list, &x1);
    globus_list_insert(&list, &x2);
    globus_list_insert(&list, &x3);
    globus_list_insert(&list, &x4);

    if(globus_list_size(list) != 4)
    {
        printf("size test failed\n");
        return -1;
    }

    i = globus_list_search(list, &x1);
    ptr = globus_list_first(i);
    if(*((int *)ptr) != x1)
    {
        printf("failed to find the first value.\n");
        return -1;
    }

    i = globus_list_search(list, &x3);
    ptr = globus_list_first(i);
    if(*((int *)ptr) != x3)
    {
        printf("failed to find the middle value.\n");
        return -1;
    }

    i = globus_list_search(list, &x4);
    ptr = globus_list_first(i);
    if(*((int *)ptr) != x4)
    {
        printf("failed to find the last value.\n");
        return -1;
    }

    i = globus_list_search(list, &x2);
    ptr = globus_list_first(i);
    if(*((int *)ptr) != x2)
    {
        printf("failed to find the middle value again.\n");
        return -1;
    }

    /* remove 2 in typical ways */
    i = globus_list_search(list, &x2);
    globus_list_remove(&list, i);
    globus_list_remove(&list, list);
    globus_list_remove(&list, list);
    globus_list_remove(&list, list);

    if(!globus_list_empty(list))
    {
        printf("test failed.  the list should be empty.\n");
        return -1;
    }

    /* reomve the rest */
    globus_list_free(list);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    printf("Success\n");
}
