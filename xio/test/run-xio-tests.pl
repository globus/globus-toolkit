#! /usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#


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
            close-cancel-test.pl
            failure-test.pl
            read-barrier-test.pl
            timeout-test.pl
            cancel-test.pl
            random-test.pl
            server-test.pl
            verify-test.pl
            attr-test.pl
            space-test.pl
            server2-test.pl
            block-barrier-test.pl
            stack-test.pl
            unload-test.pl
            );

my $runserver;
my $server_pid;

$ENV{'XIO_TEST_OUPUT_DIR'}="test_output/$$";

my $test_dir=$ENV{'XIO_TEST_OUPUT_DIR'};

system("rm -rf $test_dir");

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

eval runtests(@tests);

$@ && print "$@";

exit 0;
