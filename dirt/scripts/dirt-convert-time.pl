#!/usr/local/bin/perl

use strict;

my $timestamp = shift() || die("Missing argument!\n");

print gmtime($timestamp) . " GMT\n";

exit(0);

