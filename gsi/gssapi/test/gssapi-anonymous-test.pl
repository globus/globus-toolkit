#!/usr/bin/env perl

use strict;
use POSIX;
use Test;
use Globus::Testing::Utilities;

my $test_prog = 'gssapi-anonymous-test';

my $diff = 'diff';
my @tests;
my @todo;

Globus::Testing::Utilities::testcred_setup
    || die "Unable to set up test credentials\n";

sub basic_func
{
    my ($errors,$rc) = ("",0);
   
    $rc = system("./$test_prog 1>$test_prog.log.stdout 2>$test_prog.log.stderr") / 256;

    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }

    if($rc & 128)
    {
        $errors .= "\n# Core file generated.";
    }
   
    open(EXPECTED, "<$test_prog.stdout") || die "Couldn't open $test_prog.stdout: $!\n";
    open(LOGGED, "<$test_prog.log.stdout") || die "Couldn't open $test_prog.log.stdout: $!\n";
    $rc = 0;
    while ( my $line = <EXPECTED> )
    {
        my $logged = <LOGGED>;
        $rc++ unless ( $logged =~ /$line/ );
    }
				 
    # $rc = system("$diff $test_prog.log.stdout $test_prog.stdout") / 256;
   
   
    if($rc != 0)
    {
        $errors .= "Test produced unexpected output, see $test_prog.log.stdout";
    }


    $rc = system("$diff $test_prog.log.stderr $test_prog.stderr") / 256;
   
    if($rc != 0)
    {
        $errors .= "Test produced unexpected output, see $test_prog.log.stderr";
    }
   
    if($errors eq "")
    {
        ok('success', 'success');
      
        if( -e "$test_prog.log.stdout" )
        {
	    unlink("$test_prog.log.stdout");
        }
      
        if( -e "$test_prog.log.stderr" )
        {
	    unlink("$test_prog.log.stderr");
        } 
    }
    else
    {
        ok($errors, 'success');
    }

}

sub sig_handler
{
    if( -e "$test_prog.log.stdout" )
    {
        unlink("$test_prog.log.stdout");
    }

    if( -e "$test_prog.log.stderr" )
    {
        unlink("$test_prog.log.stderr");
    }
}

$SIG{'INT'}  = 'sig_handler';
$SIG{'QUIT'} = 'sig_handler';
$SIG{'KILL'} = 'sig_handler';


push(@tests, "basic_func();");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
