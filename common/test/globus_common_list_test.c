/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_common.h"

int matches( void * datum, void * args )
{
	/* both the datum and the args refer to pointers to int's */
	int current_item;
	int target;

	/* validate parameters */
	if ( datum == NULL || args == NULL )
		return 0;

	/* we don't really need to store the data, but this implementation
	 * helps document the code
	 */
	current_item= *(int *)(datum);
	target= *(int *)(args);
	if ( current_item == target )
		return 1;

	return 0;
}

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
	int							search_item;
    globus_list_t *             sub_list;
	int size;


    globus_module_activate(GLOBUS_COMMON_MODULE);

	printf( "checking size of null list...\n" );
	size= 10; /* to make sure the value is overridden  by the following call */
    size= globus_list_size(list);
    if( size != 0 )
    {
        printf("size test failed\n");
        return -1;
    }

	printf( "inserting first item into list...\n" );
    globus_list_insert(&list, &x1);

	printf( "checking whether globus_list_cons() adds another item...\n" );
	list= globus_list_cons( &x2, list );
	if ( list == NULL )
	{
		printf( "could not allocate new node using globus_list_cons()\n" );
		return -1;
	}
    size= globus_list_size(list);
    if( size != 2 )
    {
        printf("globus_list_cons() did not work, size is %d\n", size );
        return -1;
    }

	printf( "inserting additional items into list...\n" );
    /* globus_list_insert(&list, &x2); */
    globus_list_insert(&list, &x3);
    globus_list_insert(&list, &x4);

	printf( "checking list size again...\n" );
    if(globus_list_size(list) != 4)
    {
        printf("size test failed\n");
        return -1;
    }

	printf( "searching for items using globus_list_search()...\n" );
    sub_list = globus_list_search(list, &x1);
    ptr = globus_list_first(sub_list);
    if(*((int *)ptr) != x1)
    {
        printf("failed to find the first value.\n");
        return -1;
    }

    sub_list = globus_list_search(list, &x3);
    ptr = globus_list_first(sub_list);
    if(*((int *)ptr) != x3)
    {
        printf("failed to find the third value.\n");
        return -1;
    }

    sub_list = globus_list_search(list, &x4);
    ptr = globus_list_first(sub_list);
    if(*((int *)ptr) != x4)
    {
        printf("failed to find the last value.\n");
        return -1;
    }

    sub_list = globus_list_search(list, &x2);
    ptr = globus_list_first(sub_list);
    if(*((int *)ptr) != x2)
    {
        printf("failed to find the second value.\n");
        return -1;
    }

	printf( "searching for items using globus_list_search_pred()...\n" );
	search_item= 4;
	sub_list = globus_list_search_pred( list, matches, &search_item );
	if ( sub_list == NULL )
	{
        printf("failed to find the list item having value %d.\n", search_item );
        return -1;
	}
	search_item= 2;
	sub_list = globus_list_search_pred( list, matches, &search_item );
	if ( sub_list == NULL )
	{
        printf("failed to find the list item having value %d.\n", search_item );
        return -1;
	}
	search_item= 3;
	sub_list = globus_list_search_pred( list, matches, &search_item );
	if ( sub_list == NULL )
	{
        printf("failed to find the list item having value %d.\n", search_item );
        return -1;
	}
	search_item= 1;
	sub_list = globus_list_search_pred( list, matches, &search_item );
	if ( sub_list == NULL )
	{
        printf("failed to find the list item having value %d.\n", search_item );
        return -1;
	}

	printf( "removing items from list...\n" );
    /* remove item 2 */
    sub_list = globus_list_search(list, &x2);
    globus_list_remove(&list, sub_list);
	/* remove the first item */
    globus_list_remove(&list, list);
	/* remove the first item again */
    globus_list_remove(&list, list);
	/* remove the first item again */
    globus_list_remove(&list, list);

	printf( "verifying that list is now empty...\n" );
    if(!globus_list_empty(list))
    {
        printf("test failed; the list should be empty.\n");
        return -1;
    }

	printf( "cleaning up...\n" );
    /* reomve the rest */
    globus_list_free(list);

	globus_module_deactivate(GLOBUS_COMMON_MODULE);

    printf("Success\n");

    return 0;
}
