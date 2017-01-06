/*
 * Copyright 1999-2016 University of Chicago
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

/**
 * @file globus_eval_path_test.c
 * @brief Test the functionality of globus_eval_path()
 */

#include "globus_common.h"
#include "globus_test_tap.h"

typedef struct
{
    const char                         *name;
    const char                         *format;
    const char                         *expected;
    int                                 fail;
}
globus_eval_path_test_case_t;

int 
main(int argc, char *argv[])
{
    globus_eval_path_test_case_t        tests[] =
    {
        { "prefix", "${prefix}", prefix },
        { "mid prefix", "mid ${prefix}", "mid " prefix },
        { "prefix other", "${prefix} other", prefix " other" },
        { "exec_prefix", "${exec_prefix}", exec_prefix },
        { "mid exec_prefix", "mid ${exec_prefix}", "mid " exec_prefix },
        { "exec_prefix other", "${exec_prefix} other", exec_prefix " other" },
        { "sbindir", "${sbindir}", sbindir },
        { "mid sbindir", "mid ${sbindir}", "mid " sbindir },
        { "sbindir other", "${sbindir} other", sbindir " other" },
        { "bindir", "${bindir}", bindir },
        { "mid bindir", "mid ${bindir}", "mid " bindir },
        { "bindir other", "${bindir} other", bindir " other" },
        { "libdir", "${libdir}", libdir },
        { "mid libdir", "mid ${libdir}", "mid " libdir },
        { "libdir other", "${libdir} other", libdir " other" },
        { "libexecdir", "${libexecdir}", libexecdir },
        { "mid libexecdir", "mid ${libexecdir}", "mid " libexecdir },
        { "libexecdir other", "${libexecdir} other", libexecdir " other" },
        { "includedir", "${includedir}", includedir },
        { "mid includedir", "mid ${includedir}", "mid " includedir },
        { "includedir other", "${includedir} other", includedir " other" },
        { "datarootdir", "${datarootdir}", datarootdir },
        { "mid datarootdir", "mid ${datarootdir}", "mid " datarootdir },
        { "datarootdir other", "${datarootdir} other", datarootdir " other" },
        { "datadir", "${datadir}", datadir },
        { "mid datadir", "mid ${datadir}", "mid " datadir },
        { "datadir other", "${datadir} other", datadir " other" },
        { "mandir", "${mandir}", mandir },
        { "mid mandir", "mid ${mandir}", "mid " mandir },
        { "mandir other", "${mandir} other", mandir " other" },
        { "sysconfdir", "${sysconfdir}", sysconfdir },
        { "mid sysconfdir", "mid ${sysconfdir}", "mid " sysconfdir },
        { "sysconfdir other", "${sysconfdir} other", sysconfdir " other" },
        { "sharedstatedir", "${sharedstatedir}", sharedstatedir },
        { "mid sharedstatedir", "mid ${sharedstatedir}", "mid " sharedstatedir },
        { "sharedstatedir other", "${sharedstatedir} other", sharedstatedir " other" },
        { "localstatedir", "${localstatedir}", localstatedir },
        { "mid localstatedir", "mid ${localstatedir}", "mid " localstatedir },
        { "localstatedir other", "${localstatedir} other", localstatedir " other" },
        { "perlmoduledir", "${perlmoduledir}", perlmoduledir },
        { "mid perlmoduledir", "mid ${perlmoduledir}", "mid " perlmoduledir },
        { "perlmoduledir other", "${perlmoduledir} other", perlmoduledir " other" },
        { "undefined", "${undefined}", "" },
        { "prefixprefix", "${prefix}${prefix}", prefix prefix },
        { "prefixundefined", "${prefix}${undefined}", prefix },
        { "none", "none", "none" },
        { "half-braced", "${half-braced", "${half-braced", 1 },
        { "half-closed", "half-closed}", "half-closed}" },
        { "spare-$dollar", "spare-$dollar", "spare-$dollar" },
    };
    size_t                              num_tests = sizeof(tests)/sizeof(tests[0]);
    globus_libc_unsetenv("GLOBUS_LOCATION");
    globus_module_activate(GLOBUS_COMMON_MODULE);
    printf("1..%zu\n", num_tests);

    for (size_t i = 0; i < num_tests; i++)
    {
        char                           *s = NULL;
        globus_result_t                 result = GLOBUS_SUCCESS;

        result = globus_eval_path(tests[i].format, &s);
        if (tests[i].fail)
        {
            if (result != GLOBUS_SUCCESS)
            {
                ok (result != GLOBUS_SUCCESS, "%s (%s wasn't expected to eval)",
                    tests[i].name, tests[i].format);
            }
            else
            {
                ok (result != GLOBUS_SUCCESS, "%s (%s evaluated to %s)",
                    tests[i].name, tests[i].format, s);
            }
        }
        else
        {
            ok (result == GLOBUS_SUCCESS
                && strcmp(tests[i].expected, s) == 0,
                "%s (%s evals to %s)", tests[i].name, tests[i].format, s);
            free(s);
            s = NULL;
        }
    }
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return TEST_EXIT_CODE;
}
