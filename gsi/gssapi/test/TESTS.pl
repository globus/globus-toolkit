#!/usr/bin/env perl

my $res = system('./run-gssapi-tests.pl');
exit ( $res != 0 );
