#! /usr/bin/env perl

use strict;
use Test::Harness;
use Cwd;
use Getopt::Long;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

#$Test::Harness::verbose = 1;

unlink("test_results.txt");

@tests = qw(
            basic-test.pl
            close-barrier-test.pl
            failure-test.pl
            read-barrier-test.pl
            timeout-test.pl
            random-test.pl
            server-test.pl
            verify-test.pl
            all_in_one.pl
            );

my $runserver;
my $server_pid;

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

eval runtests(@tests);

$@ && print "$@";

exit 0;
