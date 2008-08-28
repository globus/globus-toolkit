#!/usr/bin/env perl

$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'STRICT_GT2';
system("./compare-name-test compare_name_test_strict_gt2.txt");
exit(0);
