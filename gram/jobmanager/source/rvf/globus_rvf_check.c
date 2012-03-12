/*
 * Copyright 1999-2012 University of Chicago
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
#include "globus_rvf_parser.h"
#include <libgen.h>
#include <unistd.h>

static
void
globus_l_free_record(void *value)
{
    globus_rvf_record_t *record = value;

    if (record->attribute)
    {
        free(record->attribute);
    }
    if (record->description)
    {
        free(record->description);
    }
    if (record->default_value)
    {
        free(record->default_value);
    }
    if (record->enumerated_values)
    {
        free(record->enumerated_values);
    }
    free(record);
}

static
void
print_string_value(char * aspect, char * value)
{
    printf("%s: ", aspect);

    if (strchr(value, '\n') != NULL)
    {
        putchar('"');

        while (*value)
        {
            if (*value == '"')
            {
                putchar('\\');
            }
            putchar(*value);
            value++;
        }
        putchar('"');
        putchar('\n');
    }
    else
    {
        printf("%s\n", value);
    }
}

static
void
print_when_value(char * aspect, int value)
{
    printf("%s: ", aspect);

    if (value > 0)
    {
        if (value & 1)
        {
            printf("GLOBUS_GRAM_JOB_SUBMIT ");
        }
        if (value & 2)
        {
            printf("GLOBUS_GRAM_JOB_MANAGER_RESTART ");
        }
        if (value & 4)
        {
            printf("GLOBUS_GRAM_JOB_MANAGER_STDIO_UPDATE ");
        }
    }
    putchar('\n');
}

static
void
print_bool_value(char * aspect, int value)
{
    printf("%s: %s\n", aspect, value ? "true" : "false");
}

int main(int argc, char * argv[])
{
    int i;
    int rc = 0;
    int dump=0;
    globus_module_activate(GLOBUS_COMMON_MODULE);

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) ||
            (strcmp(argv[i], "--help") == 0) ||
            (strcmp(argv[i], "-help") == 0))
        {
            printf("Usage: %s [-d|-help] RVF-FILE-PATH...\n",
                    basename(argv[0]));
            goto done;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            dump = 1;
        }
        else
        {
            break;
        }
    }

    for (; i < argc; i++)
    {
        int local_rc;
        globus_list_t *l=0;
        char * err;
        local_rc = globus_rvf_parse_file(
            argv[i],
            &l,
            &err);
        if (local_rc == 0)
        {
            if (dump)
            {
                globus_list_t * tmp;

                printf("# Parsed results from %s\n", argv[i]);

                tmp = l;
                for (tmp = l; tmp != NULL; tmp = globus_list_rest(tmp))
                {
                    globus_rvf_record_t *r;

                    r = globus_list_first(tmp);

                    print_string_value("Attribute", r->attribute);

                    if (r->description)
                    {
                        print_string_value("Description", r->description);
                    }

                    if (r->default_value)
                    {
                        print_string_value("Default", r->default_value);
                    }
                    if (r->enumerated_values)
                    {
                        print_string_value("Values", r->enumerated_values);
                    }
                    if (r->required_when != -1)
                    {
                        print_when_value("RequiredWhen", r->required_when);
                    }
                    if (r->default_when != -1)
                    {
                        print_when_value("DefaultWhen", r->default_when);
                    }
                    if (r->valid_when != -1)
                    {
                        print_when_value("ValidWhen", r->valid_when);
                    }
                    print_bool_value("Publish", r->publishable);

                    printf("\n");
                }
            }
            else
            {
                printf("%s: ok [%d record%s]\n", argv[i],
                    (int)globus_list_size(l),
                    (int)globus_list_size(l)>1 ? "s" : "");
            }
            globus_list_destroy_all(l, globus_l_free_record);
        }
        else
        {
            printf("%s\n", err);
            free(err);
            rc |= local_rc;
        }
    }

done:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return rc;
}
