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
#include <stdio.h>

#if HAVE_STRING_H
#include <string.h>
#endif

extern void
globus_i_module_dump(
    FILE *				out_f);

static int active_modules[3];

globus_bool_t
module1_activate(void);

globus_bool_t
module1_deactivate(void);

void
module1_atexit(void);

void *
module1_get_pointer_func(void);

globus_bool_t
module2_activate(void);

globus_bool_t
module2_deactivate(void);

void
module2_atexit(void);

void *
module2_get_pointer_func(void);

globus_bool_t
module3_activate(void);

globus_bool_t
module3_deactivate(void);

void
module3_atexit(void);

void *
module3_get_pointer_func(void);

static globus_module_descriptor_t module1 =
{
    "Module1",
    module1_activate,
    module1_deactivate,
    module1_atexit,
    module1_get_pointer_func
};

static globus_module_descriptor_t module2 =
{
    "Module2",
    module2_activate,
    module2_deactivate,
    module2_atexit,
    module2_get_pointer_func
};

static globus_module_descriptor_t module3 =
{
    "Module3",
    module3_activate,
    module3_deactivate,
    module3_atexit,
    module3_get_pointer_func
};


int
main(
    int					argc,
    char *				argv[])
{
    int					rc;
    void *				mod_pointer;
    char				name[20];
    char *				tmp;
    char *				value1 = "value1";
    /*char *				value2 = "value2";*/
    int					successful_tests=0;
    int					failed_tests=0;
    int					test_num=0;
    
    printf("Testing the globus_module module\n");
    
    memset(active_modules, '\0', sizeof(active_modules));

    /* Test 1: globus_module_setenv() should set the module_environment
     *         variable "GLOBUS_ENV_TEST_VAR" to "value1"
     */
    test_num++;
    strcpy(name,"GLOBUS_ENV_TEST_VAR");
    globus_module_setenv(name, value1);

    tmp = globus_module_getenv(name);
    if(strcmp(tmp, value1) != 0)
    {
	failed_tests++;
	printf("Test %d failed: globus_module_getenv() returned %s instead of %s\n",
	       test_num,
	       tmp,
	       value1);
    }
    else
    {
	successful_tests++;
    }
    
    
    /*
     * Test 2: deactivate a non-activated module
     */
    test_num++;
    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
	failed_tests++;
	printf("Test %d failed: globus_module_deactivate() returned %d\n",
	       test_num,
	       rc);
    }
    else
    {
	successful_tests++;
    }
    
    
    /*
     * Test 3: activate the globus_common_module
     */
    test_num++;
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	failed_tests++;
	printf("Test %d failed: could not activate GLOBUS_COMMON_MODULE\n",
	       test_num);
    }
    else
    {
	successful_tests++;
    }
    

    /*
     * Test 4: get a module pointer
     */
    test_num++;
    mod_pointer = globus_module_get_module_pointer(&module1);
    if(mod_pointer != (void *) 0x1)
    {
	printf("Test %d Failed: globus_module_get_module_pointer()\n",
               test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 5: activate one of our own modules
     */
    test_num++;
    
    rc = globus_module_activate(&module1);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module activation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }

    /*
     * Test 6: activate an already active module
     */
    test_num++;

    rc = globus_module_activate(&module2);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module activation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 7: activate an already active module
     */
    test_num++;

    rc = globus_module_activate(&module3);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module activation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 8: deactivate an already active module
     *         (should remain active)
     */
    test_num++;

    rc = globus_module_deactivate(&module3);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module deactivation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
   
    /*
     * Test 9: activate an already active module
     */
    test_num++;

    rc = globus_module_activate(&module3);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module activation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 10: deactivate an already active module
     *          (all should remain active except 1)
     */
    test_num++;

    rc = globus_module_deactivate(&module1);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 0 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module deactivation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 11: deactivate an already deactivated module
     *          (should not change activate state)
     */
    test_num++;

    rc = globus_module_deactivate(&module1);
    if(rc == GLOBUS_SUCCESS ||
       active_modules[0] != 0 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module deactivation\n",
	       test_num);
	
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
    
   
    /*
     * Test 12: deactivate an active module
     */
    test_num++;

    rc = globus_module_deactivate(&module2);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 0 ||
       active_modules[1] != 0 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module deactivation\n",
	       test_num);
	
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 13: deactivate an active module
     */
    test_num++;

    rc = globus_module_deactivate(&module3);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 0 ||
       active_modules[1] != 0 ||
       active_modules[2] != 0)
    {
	printf("Test %d Failed: module deactivation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 14: reactivate a module
     */
    test_num++;

    rc = globus_module_activate(&module1);
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 1 ||
       active_modules[1] != 1 ||
       active_modules[2] != 1)
    {
	printf("Test %d Failed: module activation\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }
   
    /*
     * Test 15: deactivate all modules
     */
    test_num++;
    rc = globus_module_deactivate_all();
    if(rc != GLOBUS_SUCCESS ||
       active_modules[0] != 0 ||
       active_modules[1] != 0 ||
       active_modules[2] != 0)
    {
	printf("Test %d Failed: globus_module_deactivate_all()\n",
	       test_num);
	failed_tests++;
    }
    else
    {
	successful_tests++;
    }

    /*
     * Test 16: deactivate a non-activated module
     */
    test_num++;
    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
	printf("Test %d failed: globus_module_deactivate() returned %d\n",
	       test_num,
	       rc);
	failed_tests++;
    }
    
    if(failed_tests != 0)
    {
	printf("%d of %d main tests FAILED\n",
	       failed_tests,
	       test_num);
	printf("Running atexit tests (there should be three more lines of output):\n");
	
	return 1;
    }
    else
    {
	printf("All main tests SUCCESSFUL.\n");
	printf("Running atexit tests (there should be three more lines of output):\n");
	
	return 0;
    }
}


globus_bool_t
module1_activate(void)
{
    active_modules[0]=1;
    
    globus_module_activate(&module2);
    return GLOBUS_SUCCESS;
}

globus_bool_t
module1_deactivate(void)
{
    active_modules[0]=0;

    globus_module_deactivate(&module2);
    return GLOBUS_SUCCESS;
}

void
module1_atexit(void)
{
    fprintf(stdout, "atexit test 1 successful\n");
    fflush(stdout);
}

void *
module1_get_pointer_func(void)
{
    return (void *) 0x1;
}

globus_bool_t
module2_activate(void)
{
    active_modules[1]=1;

    globus_module_activate(&module3);
    return GLOBUS_SUCCESS;
}

globus_bool_t
module2_deactivate(void)
{
    active_modules[1]=0;

    globus_module_deactivate(&module3);
    return GLOBUS_SUCCESS;
}

void
module2_atexit(void)
{
    fprintf(stdout, "atexit test 2 successful\n");
    fflush(stdout);
}

void *
module2_get_pointer_func(void)
{
    return (void *) 0x2;
}

globus_bool_t
module3_activate(void)
{
    active_modules[2]=1;

    return GLOBUS_SUCCESS;
}

globus_bool_t
module3_deactivate(void)
{
    active_modules[2]=0;

    return GLOBUS_SUCCESS;
}

void
module3_atexit(void)
{
    fprintf(stdout, "atexit test 3 successful\n");
    fflush(stdout);
}

void *
module3_get_pointer_func(void)
{
    return (void *) 0x3;
}
