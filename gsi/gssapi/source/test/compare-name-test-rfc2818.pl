#!/usr/bin/env perl

$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'STRICT_RFC2818';
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-compare_name_test_strict_rfc2818.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}
system("$valgrind ./compare-name-test compare_name_test_strict_rfc2818.txt");
exit(0);
