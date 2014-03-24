#!/usr/bin/perl

my $input = "compare_name_test.txt";

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-compare_name_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}
system("$valgrind ./compare-name-test $input");
exit($?>>8);
