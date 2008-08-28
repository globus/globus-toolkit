#!/usr/bin/env perl

$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'STRICT_RFC2818';
system("./compare-name-test compare_name_test_strict_rfc2818.txt");
exit(0);
