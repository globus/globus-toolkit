#!/usr/bin/env perl

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-inquire_names_for_mech_test.log";
}
system("$valgrind ./inquire-names-for-mech-test");
exit(0);
