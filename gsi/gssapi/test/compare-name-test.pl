#!/usr/bin/env perl

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-compare_name_test.log";
}
system("$valgrind ./compare-name-test compare_name_test.txt");
exit(0);
