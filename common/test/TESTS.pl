#!/usr/bin/env perl

my $res = system('./run-common-tests.pl');
exit ( $res != 0 );

