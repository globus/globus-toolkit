#!/usr/bin/env perl

$ENV{GLOBUS_GSSAPI_NAME_COMPATIBILITY} = 'STRICT_RFC2818';
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-compare_name_test_strict_rfc2818.log";
}
system("$valgrind ./compare-name-test compare_name_test_strict_rfc2818.txt");
exit(0);
