#!/usr/bin/perl

use strict;
use IO::Handle;

my $startCount = scalar($ARGV[0]);
my $endCount = scalar($ARGV[1]);

STDOUT->autoflush(1);

for (my $index=$startCount; $index<=$endCount; $index*=2) {
    my $testOutputFile = "throughput-test-" . $index . ".log";
    my $testExec = "ant -Djob.count=" . $index . " runTestApp";

    open TESTLOG, ">$testOutputFile" or die "Error: unable to open file "
        . $testOutputFile . "for writing";
    open EXEC, "$testExec |" or die "Error: unable to execute command \'"
        . $testExec . "\'";
        while (<EXEC>) {
            print TESTLOG;
        }
    close EXEC;
    close TESTLOG;

    my $timingsOutputFile = "throughput-timings-" . $index . ".html";
    my $timingsExec = "./parse-timings.pl " . $testOutputFile;

    open TIMINGSLOG, ">$timingsOutputFile" or die "Error: unable to open file "
        . $timingsOutputFile . "for writing";
    open EXEC, "$timingsExec |" or die "Error: unable to execute command \'"
        . $timingsExec . "\'";
        while (<EXEC>) {
            print TIMINGSLOG;
        }
    close EXEC;
    close TIMINGSLOG;
}
