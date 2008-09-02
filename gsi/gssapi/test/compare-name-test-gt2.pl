#!/usr/bin/env perl

$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'STRICT_GT2';
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-compare_name_test_strict_gt2.log";
}
system("$valgrind ./compare-name-test compare_name_test_strict_gt2.txt");
exit(0);
