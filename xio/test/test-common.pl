#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

sub run_test
{
    my $f;
    my @lst;
    my $cmd=(shift);
    my $test_str=(shift);
    my ($errors,$rc) = ("",0);
    my $output_dir=$ENV{'XIO_TEST_OUPUT_DIR'};

    # delete the output dir if it exists
    $rc = system("mkdir -p $output_dir");
    $rc = system("rm -f $output_dir/$test_str.insure");
    $rc = system("rm -f $output_dir/$test_str.dbg");
    $rc = system("rm -f $output_dir/$test_str.err");
    $rc = system("rm -f $output_dir/$test_str.out");

    $ENV{"INSURE_REPORT_FILE_NAME"} = "$output_dir/$test_str.insure";
    if(!defined($ENV{"XIO_TEST_NO_DEBUG"}))
    {
        $ENV{"GLOBUS_XIO_DEBUG"} = "ALL,#$output_dir/$test_str.dbg,1";
    }
    if(!defined($ENV{"GLOBUS_CALLBACK_POLLING_THREADS"}))
    {
        $ENV{"GLOBUS_CALLBACK_POLLING_THREADS"} = "2";
    }

    my $command = "$cmd > $output_dir/$test_str.out 2> $output_dir/$test_str.err";
    if(defined($ENV{"XIO_TEST_EF"}))
    {
        $command = "ef $command";
    }
    elsif(defined($ENV{"XIO_TEST_VALGRIND"}))
    {
        $ENV{"VALGRIND_OPTS"} = "-q --error-limit=no --num-callers=10 " .
            "--profile=no --leak-check=yes --leak-resolution=med " .
            "--freelist-vol=10000000 --logfile=$output_dir/$test_str.valgrind";
        $command = "valgrind $command";
    }

    $rc = system($command);
    if($rc != 0)
    {
        $errors .= "\n # Tests :$command: exited with  $rc.";
    }
    @lst=`ls core* 2> /dev/null`;
    if($#lst >= 0)
    {
        my $l_core= $lst[0];
        my $core_str = "$output_dir/$test_str.core";
        chomp($l_core);

        $errors .= "\n# mv $l_core $core_str\n";
        system("mv $l_core $core_str");
        $errors .= "\n# Core file generated." . $errors;
        unlink($l_core);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        my $filename="$output_dir/$test_str.fail";
        open(FAIL, ">$filename");
        print FAIL "\n";
        print FAIL "Test :$test_str: failed with :$rc:\n";
        print FAIL "stdout :$output_dir/$test_str.out:\n";
        print FAIL "stderr :$output_dir/$test_str.err:\n";
        if(-r "$output_dir/$test_str.core")
        {
            print FAIL "core: $output_dir/$test_str.core\n";
        }
        print FAIL "cmd :$cmd\n";
        close(FAIL);

        $errors .= "\n# Test failed\n# $cmd\n# " . $errors;
        ok($errors, 'success');
    }
}1;
