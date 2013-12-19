#!/usr/bin/env perl

=pod

=head1 Tests for the globus openssl error code

Tests to exercise the error handling functionality of the globus
 openssl error library.

=cut

use strict;
use Test::More;
use File::Basename;
use lib dirname($0);

$ENV{PATH} = dirname($0).":.:".$ENV{PATH};
my $test_prog = 'globus_openssl_error_test';
my $stdoutfile = dirname($0)."/$test_prog.stdout";
my @tests;
my @todo;

sub basic_func
{
    my ($errors,$rc) = ("",0);
    ok($rc = system("$test_prog 1>$test_prog.log.stdout 2>$test_prog.log.stderr") == 0, "run $test_prog");

    ok(open(EXPECTED, "<$stdoutfile"), "Open $stdoutfile");
    ok(open(LOGGED, "<$test_prog.log.stdout"), "Open $test_prog.log.stdout");
    $rc = 0;
    while ( my $line = <EXPECTED> )
    {
        my $logged = <LOGGED>;
        $rc++ unless ( $logged =~ /$line/ );
    }
    ok($rc == 0, "Match reference output");
}

sub sig_handler
{
    if( -e "$test_prog.log.stdout" )
    {
        unlink("$test_prog.log.stdout");
    }
}

$SIG{'INT'}  = 'sig_handler';
$SIG{'QUIT'} = 'sig_handler';
$SIG{'KILL'} = 'sig_handler';


push(@tests, "basic_func();");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => 4*scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
