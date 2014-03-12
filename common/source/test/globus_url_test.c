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

/** @file globus_url_test.c Tests for the Globus URL parser */

#include "globus_common.h"
#include <stdio.h>

typedef struct
{
    char *			url;
    int				result;
    globus_url_t		url_result;
} test_url_t;

int compare_ints(int a, int b, int test_num, const char * label)
{
    if(a != b)
    {
        fprintf(stderr,
	    "test %d: FAILED (%s parsed to %d instead of %d)\n",
	    test_num,
	    label,
	    a,
	    b);
        return GLOBUS_FALSE;
    }
    else
    {
        return GLOBUS_TRUE;
    }
}

int compare_strings(const char *a, const char *b, int test_num, const char * label)
{
    if(a == b && a == NULL)
    {
        return GLOBUS_TRUE;
    }
    else if((a == NULL ||
        b == NULL) &&
        a != b)
    {
        fprintf(stderr,
	    "test %d: FAILED (%s parsed to %s instead of %s)\n",
	    test_num,
	    label,
	    a == NULL ? "NULL" : a,
	    b == NULL ? "NULL" : b);

        return GLOBUS_FALSE;
    }
    else if(strcmp(a,b) != 0)
    {
        fprintf(stderr,
	    "test %d: FAILED (%s parsed to %s instead of %s)\n",
	    test_num,
	    label,
	    a,
	    b);

        return GLOBUS_FALSE;
    }
    else
    {
        return GLOBUS_TRUE;
    }
}

/**
 * @brief Test the Globus URL parser
 * @details
 * Exercise the globus_url_parse() function with a set of valid and invalid
 * URL strings.
 */
int test_globus_url(void)
{
    int i;
    int num_failed=0;
    int ok;
    int result;
    globus_url_t  url;
#if _WIN32
#define BIN_SH "\\bin\\sh"
#else
#define BIN_SH "/bin/sh"
#endif

    test_url_t test_urls[] =
    {
        /** @test
         * Parse well-formed FTP URL containing scheme, host, and path
         * with globus_url_parse()
         */
        { "ftp://ftp.mcs.anl.gov/pub/foobar", GLOBUS_SUCCESS,
          {
            "ftp",
            GLOBUS_URL_SCHEME_FTP,
            NULL,
            NULL,
            "ftp.mcs.anl.gov",
            0,
            "/pub/foobar",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /** @test
         * Parse well-formed FTP URL containing scheme, username, hex-encoded
         * password, host, and path with globus_url_parse()
         */
        { "ftp://user:%73%65%63%72%65%74@ftp.mcs.anl.gov/pub/foobar", GLOBUS_SUCCESS,
          {
            "ftp",
            GLOBUS_URL_SCHEME_FTP,
            "user",
            "secret",
            "ftp.mcs.anl.gov",
            0,
            "/pub/foobar",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /** @test
         * Parse well-formed HTTP URL containing scheme and host
         * with globus_url_parse()
         */
        { "http://www.globus.org", GLOBUS_SUCCESS,
          {
            "http",
            GLOBUS_URL_SCHEME_HTTP,
            NULL,
            NULL,
            "www.globus.org",
            0,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /** @test
         * Parse a well-formed HTTP URL containing scheme, host, and
         * partially hex-encoded path
         * with globus_url_parse()
         */
        { "http://www.globus.org/%7Ebester", GLOBUS_SUCCESS,
          {
            "http",
            GLOBUS_URL_SCHEME_HTTP,
            NULL,
            NULL,
            "www.globus.org",
            0,
            "/~bester",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse and absolute file URL
         */
        { "file:///bin/sh", GLOBUS_SUCCESS,
          {
            "file",
            GLOBUS_URL_SCHEME_FILE,
            NULL,
            NULL,
            NULL,
            0,
            BIN_SH,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an absolute file URL with a host component
         */
        { "file://localhost/bin/sh", GLOBUS_SUCCESS,
          {
            "file",
            GLOBUS_URL_SCHEME_FILE,
            NULL,
            NULL,
            "localhost",
            0,
            BIN_SH,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an absolute file URL with a host component
         */
        { "file://mcs.anl.gov/bin/sh", GLOBUS_SUCCESS,
          {
            "file",
            GLOBUS_URL_SCHEME_FILE,
            NULL,
            NULL,
            "mcs.anl.gov",
            0,
            BIN_SH,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an absolute file URL with several leading /s
         */
        { "file:////bin/sh", GLOBUS_SUCCESS,
          {
            "file",
            GLOBUS_URL_SCHEME_FILE,
            NULL,
            NULL,
            NULL,
            0,
            BIN_SH,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an absolute file url with only one / after the initial :
         */
        { "file:/bin/sh", GLOBUS_SUCCESS,
          {
            "file",
            GLOBUS_URL_SCHEME_FILE,
            NULL,
            NULL,
            NULL,
            0,
            BIN_SH,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an ftp url with username, password, host, path
         */
        { "ftp://bester:password@ftp.mcs.anl.gov/pub/foo", GLOBUS_SUCCESS,
          {
            "ftp",
            GLOBUS_URL_SCHEME_FTP,
            "bester",
            "password",
            "ftp.mcs.anl.gov",
            0,
            "/pub/foo",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an x-nexus URL
         */
        { "x-nexus://pitcairn-9.mcs.anl.gov:8713", GLOBUS_SUCCESS,
          {
            "x-nexus",
            GLOBUS_URL_SCHEME_X_NEXUS,
            NULL,
            NULL,
            "pitcairn-9.mcs.anl.gov",
            8713,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
          }
        },
        /**
         * @test
         * Parse an ldap URL
         */
        { "ldap://mds.globus.org/o=Globus,c=US?dn?SUBTREE?hn=pitcairn.mcs.anl.gov-fork", GLOBUS_SUCCESS,
          {
            "ldap",
            GLOBUS_URL_SCHEME_LDAP,
            NULL,
            NULL,
            "mds.globus.org",
            0,
            NULL,
            "o=Globus,c=US",
            "dn",
            "SUBTREE",
            "hn=pitcairn.mcs.anl.gov-fork",
            NULL
          }
        },
        /** 
         * @test Parse an ldap URL
         */
        { "ldap://mds.globus.org/ou=MCS,%20o=Argonne%20National%20Laboratory,%20o=Globus,%20c=US?dn?SUBTREE?hn=pitcairn.mcs.anl.gov-fork", GLOBUS_SUCCESS,
          {
            "ldap",
            GLOBUS_URL_SCHEME_LDAP,
            NULL,
            NULL,
            "mds.globus.org",
            0,
            NULL,
            "ou=MCS, o=Argonne National Laboratory, o=Globus, c=US",
            "dn",
            "SUBTREE",
            "hn=pitcairn.mcs.anl.gov-fork",
            NULL
          }
        },
        /**
         * @test
         * Parse a URL with a non-standard URL scheme
         */
        { "x123://foo_this", GLOBUS_SUCCESS,
          {
            "x123",
            GLOBUS_URL_SCHEME_UNKNOWN,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            "foo_this"
          }
        },
        /**
         * @test
         * URL failure with bad ldap attributes
         */
        { "ldap://mds.globus.org/o=Globus,c=US?%%?SUBTREE?hn=pitcairn.mcs.anl.gov-fork", GLOBUS_URL_ERROR_BAD_ATTRIBUTES },
        /**
         * @test
         * URL failure with bad ldap URL
         */
        { "ldap://mds.globus.org/ou=MCS,o=Argonne National Laboratory, o=Globus, c=US?dn?hn=pitcairn.mcs.anl.gov-fork", GLOBUS_URL_ERROR_BAD_DN },
        /** @test URL failure with bad ftp path */
        { "ftp://host:123/\\", GLOBUS_URL_ERROR_BAD_PATH },
        /** @test URL failure with bad ftp port */
        { "ftp://user:\\@host/foo", GLOBUS_URL_ERROR_BAD_PORT },
        /** @test URL failure with bad ftp port */
        { "ftp://host:asdf/foo", GLOBUS_URL_ERROR_BAD_PORT },
        /** @test URL failure with bad nexus host */
        { "x-nexus://bad\\host\\:123", GLOBUS_URL_ERROR_BAD_HOST },
        /** @test URL failure with bad nexus host */
        { "x-nexus://\\\\", GLOBUS_URL_ERROR_BAD_HOST },
        /** @test URL failure with bad ftp user */
        { "ftp://bester:huh%%@ftp.mcs.anl.gov/pub/foo", GLOBUS_URL_ERROR_BAD_USER },
        /** @test URL failure with bad ftp user */
        { "ftp://foo%%@host/foo", GLOBUS_URL_ERROR_BAD_USER },
        /** @test URL failure with bad ftp user */
        { "ftp://huh%%@ftp.mcs.anl.gov/pub/foo", GLOBUS_URL_ERROR_BAD_USER },
        /** @test URL failure with bad file path */
        { "file:bin/sh", GLOBUS_URL_ERROR_BAD_PATH },
        /** @test URL failure with bad file path */
        { "file://hostname", GLOBUS_URL_ERROR_BAD_PATH },
        /** @test URL failure with bad ftp scheme */
        { "ftp:/", GLOBUS_URL_ERROR_BAD_SCHEME },
        /** @test URL failure with bad scheme */
        { "://\\@host/foo", GLOBUS_URL_ERROR_BAD_SCHEME },
        /** @test URL failure with bad scheme */
        { "X123://foo_this", GLOBUS_URL_ERROR_BAD_SCHEME },
        { NULL, GLOBUS_URL_ERROR_NULL_STRING },
    };

#define NUM_TESTS (int)(sizeof(test_urls) / sizeof(test_url_t))
    printf("1..%d\n", NUM_TESTS);
    for(i = 0; i < NUM_TESTS; i++)
    {
	ok = GLOBUS_TRUE;

	result = globus_url_parse(test_urls[i].url, &url);

	if(result != test_urls[i].result)
	{
	    fprintf(stderr,
		"test %d: FAILED (url=%s, expected %d, parse returned %d)\n",
		i+1,
		test_urls[i].url,
		test_urls[i].result,
		result);
	    ok = GLOBUS_FALSE;
	}
	
	if(test_urls[i].result == GLOBUS_SUCCESS)
	{
            /* Verify that parse did what we wanted it to do */
            if(!compare_strings(url.scheme,
                                test_urls[i].url_result.scheme,
				i+1,
				"scheme"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_ints(url.scheme_type,
	                     test_urls[i].url_result.scheme_type,
			     i+1,
			     "scheme_type"))
	    {
                ok = GLOBUS_FALSE;
	    }
            if(!compare_strings(url.user,
                                test_urls[i].url_result.user,
				i+1,
				"user"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.password,
                                test_urls[i].url_result.password,
				i+1,
				"password"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.host,
                                test_urls[i].url_result.host,
				i+1,
				"host"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_ints((int) url.port,
                                (int) test_urls[i].url_result.port,
				i+1,
				"port"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.url_path,
                                test_urls[i].url_result.url_path,
				i+1,
				"url_path"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.dn,
                                test_urls[i].url_result.dn,
				i+1,
				"dn"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.attributes,
                                test_urls[i].url_result.attributes,
				i+1,
				"attributes"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.scope,
                                test_urls[i].url_result.scope,
				i+1,
				"scope"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.filter,
                                test_urls[i].url_result.filter,
				i+1,
				"filter"))
            {
                ok = GLOBUS_FALSE;
            } 
            if(!compare_strings(url.url_specific_part,
                                test_urls[i].url_result.url_specific_part,
				i+1,
				"url_specific_part"))
            {
                ok = GLOBUS_FALSE;
            } 

	    result = globus_url_destroy(&url);
	    if(result != GLOBUS_SUCCESS)
	    {
		fprintf(stderr,
		    "test %d: FAILED (could not destroy parsed url)\n",
		     i+1);
		ok = GLOBUS_FALSE;
	    }
	}
	if(!ok)
	{
	    num_failed++;
	}
        printf("%s %d %s\n", ok?"ok":"not ok", i+1, test_urls[i].url?test_urls[i].url:"NULL");
    }
    return num_failed;
}

int main(int argc, char *argv[])
{
    int           i;
    int           result;
    int		  rc;
    globus_url_t  url;
    
    globus_module_activate(GLOBUS_COMMON_MODULE);

    if(argc > 1)
    {
        printf("Bypassing standard tests, parsing command line arguments\n");
        for(i = 1; i < argc; i++)
        {
	    printf("Parsing \"%s\"\n", argv[i]);
	    result = globus_url_parse(argv[i], &url);
	    printf("Parse returned %d\n", result);
	    if(result == GLOBUS_SUCCESS)
	    {
#define printable_string(x) (x==NULL ? "NULL" : x)

	        printf("url_scheme        = \"%s\"\n"
		                   "url_scheme_type   = %d\n"
				   "user              = \"%s\"\n"
				   "password          = \"%s\"\n"
				   "host              = \"%s\"\n"
				   "port              = %u\n"
				   "url_path          = \"%s\"\n"
				   "dn                = \"%s\"\n"
				   "attributes        = \"%s\"\n"
				   "scope             = \"%s\"\n"
				   "filter            = \"%s\"\n"
				   "url_specific_part = \"%s\"\n",
				   printable_string(url.scheme),
				   url.scheme_type,
				   printable_string(url.user),
				   printable_string(url.password),
				   printable_string(url.host),
				   url.port,
				   printable_string(url.url_path),
				   printable_string(url.dn),
				   printable_string(url.attributes),
				   printable_string(url.scope),
				   printable_string(url.filter),
				   printable_string(url.url_specific_part));

	        result = globus_url_destroy(&url);
		printf("globus_url_destroy returned %d\n", result);
	    }
        }
        globus_module_deactivate_all();
        return 0;
    }
    else
    {
        rc = test_globus_url();
    }

    globus_module_deactivate_all();
    return rc;
}
