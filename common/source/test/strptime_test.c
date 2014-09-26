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

/**
 * @file strptime_test.c
 * @brief Test the functionality in globus_strptime.c
 */

#include "globus_common.h"
#include "globus_test_tap.h"
#include <locale.h>

#define printError(a,b,c) printf("%s", a)
int 
main(int argc, char *argv[])
{
    char                               *rc;
    char                                dateString[256];
    char                                formatString[256];
    char                                resultString[256];
    struct tm                           timeStruct;
    int                                 skip_c99_formats = 0;

#if __MINGW32__
    skip_c99_formats = 1;
#endif
    setvbuf(stdout, NULL, _IONBF, 0);

    setlocale(LC_ALL, "C");
    printf("1..45\n");

    globus_module_activate(GLOBUS_COMMON_MODULE);

    /* create timestamp strings & check them against the tm struct */
    /* "good news" version- format and data match exactly */
    strcpy(formatString, "%a %b %d %H:%M:%S %Y");
    strcpy(dateString, "Sun May 01 20:27:01 1994");
    printf(" Input date: %s\n", dateString);
    rc = globus_strptime(dateString, formatString, &timeStruct);
    ok(rc != NULL, "globus_strptime_whitespace_match");
    ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %H:%M:%S %Y", &timeStruct) > 0,
        "reformat_whitespace_match");
    ok(strcmp(resultString, dateString) == 0, "compare_whitespace_match");

    /* neither format nor data has whitespace */
    strcpy(formatString, "%a%b%d%H:%M:%S%Y");
    strcpy(dateString, "SunMay0120:27:011994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_no_whitespace");
    ok(strftime(resultString, sizeof(resultString),
        "%a%b%d%H:%M:%S%Y", &timeStruct) > 0,
        "reformat_no_whitespace");
    ok(strcmp(resultString, dateString) == 0, "compare_nowhitespace_match");

    /* format has whitespace but data does not */
    strcpy(formatString, "%a %b %d %H:%M:%S %Y");
    strcpy(dateString, "SunMay0120:27:011994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_dnws_fws");
    ok(strftime(resultString, sizeof(resultString),
        "%a%b%d%H:%M:%S%Y", &timeStruct) > 0,
        "reformat_from_ws_to_nows");
    ok(strcmp(resultString, dateString) == 0, "compare_from_ws_to_nows");

    /* data has whitespace but format does not */
    strcpy(formatString, "%a%b%d%H:%M:%S%Y");
    strcpy(dateString, "Sun May 01 20:27:01 1994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_dws_fnws");
    ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %H:%M:%S %Y", &timeStruct) > 0,
        "reformat_from_nows_to_ws");
    ok(strcmp(resultString, dateString) == 0, "compare_from_nows_to_ws");

    /* variations on the format */
    strcpy(formatString, "%a %b %d %H:%M:%S %C%y");
    strcpy(dateString, "Sun May 01 20:27:01 19 94");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_ws_century_year_variation");
    skip(skip_c99_formats, ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %H:%M:%S %C %y", &timeStruct) > 0,
        "reformat_century_year_variation"));
    skip(skip_c99_formats, ok(strcmp(resultString, dateString) == 0, "compare_century_year_variation"));

    strcpy(formatString, "%a %D %H:%M:%S");
    strcpy(dateString, "Sun 5/01/94 20:27:01");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_date_variation");
    skip(skip_c99_formats, ok(strftime(resultString, sizeof(resultString),
        "%a %D %H:%M:%S", &timeStruct) > 0,
        "reformat_date_variation"));
    /* Hack to work around strftime adding a leading zero to the month */
    memmove(resultString+4, resultString+5, strlen(resultString+4));
    skip(skip_c99_formats, ok(strcmp(resultString, dateString) == 0, "compare_date_variation"));

    strcpy(formatString, "%a %b %d %I:%M:%S %p %Y");
    strcpy(dateString, "Sun May 01 09:27:01 a.m. 1994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_am_variation");
    /* Some strftimes or locales? use AM instead of a.m. */
    ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %I:%M:%S a.m. %Y", &timeStruct) > 0,
        "reformat_am_variation");
    ok(strcmp(resultString, dateString) == 0, "compare_am_variation");

    strcpy(formatString, "%a %b %d %I:%M:%S %p %Y");
    strcpy(dateString, "Sun May 01 09:27:01 p.m. 1994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_pm_variation");
    /* Some strftimes or locales? use PM instead of p.m. */
    ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %I:%M:%S p.m. %Y", &timeStruct) > 0,
        "reformat_pm_variation");
    ok(strcmp(resultString, dateString) == 0, "compare_pm_variation");

    strcpy(formatString, "%a %b %d %I:%M:%S %Y");
    strcpy(dateString, "Sun May 01 09:27:01 1994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_no_ampm_variation");
    ok(strftime(resultString, sizeof(resultString),
        "%a %b %d %I:%M:%S %Y", &timeStruct) > 0,
        "reformat_no_ampm_variation");
    ok(strcmp(resultString, dateString) == 0, "compare_no_ampm_variation");

    strcpy(formatString, "%a %B %d %R %Y");
    strcpy(dateString, "Sun May 01 20:27 1994");
    printf(" Input date: %s\n", dateString);
    skip(skip_c99_formats, ok(
        globus_strptime(dateString, formatString, &timeStruct) != NULL,
       "globus_strptime_R_variation"));
    skip(skip_c99_formats, ok(strftime(resultString, sizeof(resultString),
        formatString, &timeStruct) > 0, "reformat_R_variation"));
    skip(skip_c99_formats, ok(
        strcmp(resultString, dateString) == 0, "compare_R_variation"));

    strcpy(formatString, "%a %b %d %T %Y");
    strcpy(dateString, "Sun Jun 01 21:27:01 1994");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_abbrev_month");
    skip(skip_c99_formats, ok(strftime(resultString, sizeof(resultString),
        formatString, &timeStruct) > 0, "reformat_abbrev_month"));
    skip(skip_c99_formats, ok(strcmp(resultString, dateString) == 0, "compare_abbrev_month"));

    strcpy(formatString, "%a %b %d %H:%M:%S %y");
    strcpy(dateString, "Sun May 01 20:27:01 94");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_year_no_century_large");
    ok(strftime(resultString, sizeof(resultString),
        formatString, &timeStruct) > 0, "reformat_year_no_century_large");
    ok(strcmp(dateString, resultString) == 0, "compare_year_no_century_large");

    strcpy(formatString, "%a %b %d %H:%M:%S %y");
    strcpy(dateString, "Sun May 01 20:27:01 02");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_no_century_small");
    ok(strftime(resultString, sizeof(resultString),
        formatString, &timeStruct) > 0, "reformat_year_no_century_small");
    ok(strcmp(dateString, resultString) == 0, "compare_year_no_century_small");

    /* time only */
    strcpy(formatString, "%R");
    strcpy(dateString, "20:27");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_time_only");
    skip(skip_c99_formats, ok(strftime(resultString, sizeof(resultString),
       formatString, &timeStruct) > 0, "reformat_time_only"));
    skip(skip_c99_formats, ok(strcmp(dateString, resultString) == 0, "compare_time_only"));

    /* date only */
    strcpy(formatString, "%a %b %d %y");
    strcpy(dateString, "Sun May 01 02");
    printf(" Input date: %s\n", dateString);
    ok(globus_strptime(dateString, formatString, &timeStruct) != NULL,
        "globus_strptime_date_only");
    ok(strftime(resultString, sizeof(resultString),
        formatString, &timeStruct) > 0, "reformat_date_only");
    ok(strcmp(dateString, resultString) == 0, "compare_date_only");

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return TEST_EXIT_CODE;
}
