#!/usr/bin/env perl

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_import_name.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}
system("$valgrind ./gssapi-import-name");
exit(0);
