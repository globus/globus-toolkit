#!/usr/bin/env perl

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --leak-check=full --log-file=VALGRIND-gssapi_import_name.log";
}
system("$valgrind ./gssapi-import-name");
exit(0);
