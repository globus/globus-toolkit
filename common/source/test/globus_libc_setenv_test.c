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

/** globus_libc_setenv_test.c Test the functionality in globus_libc_setenv.c
 * @author by Michael Lebman
 */

#include "globus_common.h"
#include "globus_test_tap.h"

struct envVar
{
    char           *name;
    char           *value;
};

int 
globus_libc_setenv_test(void)
{
    struct envVar                       vars[] = {{"var0", "val0"},
    {"var1", "val1"},
    {"var2", "val2"},
    {"var3", "val3"},
    {"var4", "val4"},
    {"var5", "val5"},
    {"var6", "val6"},
    {"var7", "val7"},
    {"var8", "val8"},
    {"var9", "val9"},
    {"var10", "val10"},
    {"var11", "val11"},
    {"var12", "val12"},
    {"var13", "val13"},
    {"var14", "val14"},
    {"var15", "val15"},
    {"var16", "val16"},
    {"var17", "val17"},
    {"var18", "val18"},
    {"var19", "val19"},
    {"var20", "val20"},
    {"var21", "val21"},
    {"var22", "val22"},
    {"var23", "val23"},
    {"var24", "val24"},
    {"var25", "val25"},
    {"var26", "val26"},
    {"var27", "val27"},
    {"var28", "val28"},
    {"var29", "val29"},
    {"var30", "val30"},
    {"var31", "val31"},
    {"var32", "val32"},
    {"var33", "val33"},
    {"var34", "val34"},
    {"var35", "val35"},
    {"var36", "val36"},
    {"var37", "val37"},
    {"var38", "val38"},
    {"var39", "val39"},
    {"var40", "val40"},
    {"var41", "val41"},
    {"var42", "val42"},
    {"var43", "val43"},
    {"var44", "val44"},
    {"var45", "val45"},
    {"var46", "val46"},
    {"var47", "val47"},
    {"var48", "val48"},
    {"var49", "val49"}};
    int                                 i;
    char                               *value;
    char                                temp[256];

    printf("1..330\n");
    globus_module_activate(GLOBUS_COMMON_MODULE);

    for (i = 40; i < 50; i++)
    {
        ok((value = getenv(vars[i].name)) == NULL,
            "variable_%s_shouldnt_exist", vars[i].name);
    }

    /* add a bunch of variables to the environment */
    printf("    Setting environment variables...\n");
    for (i = 0; i < 50; i++)
    {
        ok(globus_libc_setenv(vars[i].name, vars[i].value, 0) == 0,
            "globus_libc_setenv_%s", vars[i].name);
    }

    /**
     * @test 
     * Check to see whether all of the variables were added correctly,
     * then make sure they stay the same if overwrite is false and change
     * if it is true.
     */
    printf("    Verifying set environment variables...\n");
    for (i = 0; i < 50; i++)
    {
        ok((value = getenv(vars[i].name)) != NULL,
            "getenv_%s", vars[i].name);
        strcpy(temp, vars[i].name);
        temp[2] = 'l';      /* overwrite the 'r' with an 'l' */
        skip(value == NULL,
            ok(globus_libc_setenv(vars[i].name, temp, 0) == 0,
            "set_%s_without_overwrite", vars[i].name));
        skip(value == NULL,
            ok(strcmp(getenv(vars[i].name), vars[i].value) == 0,
            "compare_%s_after_not_changing", vars[i].name));
        skip(value == NULL,
            ok(globus_libc_setenv(vars[i].name, temp, 1) == 0,
                "set_%s_with_overwrite", vars[i].name));
        skip(value == NULL,
            ok(strcmp(getenv(vars[i].name), temp) == 0,
                "compare_%s_after_changing", vars[i].name));
    }

    /**
     * @test unset most of the variables with globus_libc_unsetenv()
     */
    printf("    Unsetting environment variables...\n");
    for (i = 10; i < 50; i++)
    {
        printf("    Unsetting %s\n", vars[i].name);
        globus_libc_unsetenv(vars[i].name);
    }

    /** @test check again for their presence; include both set and unset
     * variables
     */
    printf("    Checking set environment variables...\n");
    for (i = 0; i < 10; i++)    /* should still be present */
    {
        ok(getenv(vars[i].name) != NULL,
            "test_that_not_unset_%s_is_set", vars[i].name);
    }
    printf("    Checking unset environment variables...\n");
    for (i = 10; i < 20; i++)   /* should be unset */
    {
        ok((value = getenv(vars[i].name)) == NULL,
            "test_that_%s_is_unset", vars[i].name);
        if (value)
        {
            printf("  UNEXPECTED VALUE %s\n", value);  
        }
    }

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return TEST_EXIT_CODE;
}

int main(int argc, char *argv[])
{
    return globus_libc_setenv_test();
}
