#!/usr/bin/perl

use strict;
use IO::Handle;
use Getopt::Long;

my ($verbose,   $host,  $port,  $startCount,    $endCount) =
   (1,          "",     8080,   1,              1);

GetOptions(
    "v|verbose!"        => \$verbose,
    "h|host=s"          => \$host,
    "p|port=s"          => \$port,
    "s|startcount=s"    => \$startCount,
    "e|endcount=s"      => \$endCount)
    or pod2usage(2);

if (!length($host)) {
    print "ERROR: no host specified\n";
    exit 1;
}

if ($verbose) {
    print   "Host: $host\n"
          . "Port: $port\n"
          . "Start Count: $startCount\n"
          . "End Count: $endCount\n";
}

STDOUT->autoflush(1);
TESTLOG->autoflush(1);
TIMINGSLOG->autoflush(1);

for (my $index=$startCount; $index<=$endCount; $index*=2) {
    my $testOutputFile = "throughput-test-" . $index . ".log";
    my $testExec = "ant "
                 . "-Dservice.host=$host "
                 . "-Dservice.port=$port "
                 . "-Djob.count=$index "
                 . "-Dogsa.root=$ENV{GLOBUS_LOCATION} "
                 . "runTestApp";

    open TESTLOG, ">$testOutputFile" or die "Error: unable to open file "
        . $testOutputFile . "for writing";
    open EXEC, "$testExec |" or die "Error: unable to execute command \'"
        . $testExec . "\'";
        while (<EXEC>) {
            if ($verbose) {
                print;
            }
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
            if ($verbose) {
                print;
            }
            print TIMINGSLOG;
        }
    close EXEC;
    close TIMINGSLOG;
}
