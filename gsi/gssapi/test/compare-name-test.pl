#!/usr/bin/env perl

my $valgrind = "";
$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'HYBRID';
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-compare_name_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}
system("$valgrind ./compare-name-test compare_name_test.txt");
exit(0);
