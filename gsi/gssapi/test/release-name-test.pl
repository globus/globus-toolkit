#!/usr/bin/env perl

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-release_name_test.log";
}
system("$valgrind ./release-name-test");
exit(0);
