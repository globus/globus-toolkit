#!/usr/bin/perl

use strict;
use IO::Handle;
use Getopt::Long;
use Pod::Usage;

my $hostname = `$ENV{GLOBUS_LOCATION}/libexec/globus-libc-hostname`;

my ($verbose,   $host,  $port,  $startCount,    $endCount,  $factoryType) =
   (1,          "",     8080,   1,              1,          "Fork");
my ($help,  $man) =
   (0,      0);

GetOptions(
    "verbose!"      => \$verbose,
    "host=s"        => \$host,
    "port=s"        => \$port,
    "startcount=s"  => \$startCount,
    "endcount=s"    => \$endCount,
    "type=s"        => \$factoryType,
    "help"          => \$help,
    "man"           => \$man)
    or pod2usage(2);

if ($help or $man) {
    pod2usage(2) if $help;
    pod2usage(1) if $man;
}

if (!length($host)) {
    chomp($hostname);
    $host = $hostname;
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
                 . "-Dfactory.type=$factoryType "
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
END{};
1;

=head1 NAME

run-throughput-tests.pl - MJS throughput test script

=head1 SYNOPSIS

run-throughput-tests.pl [options]

Options:

    --host=<host>                   Specify the host of the running MHE
                                    to test against (default is the
                                    hostname of the local machine)
    --port=<port>                   Specify the port of the running MHE
                                    to test against (default is 8080)
    --type=<type>                   Specify the factory type to test against
                                    (default is "Fork")
    --startcount=<count>            Specify the first test case's job count
                                    (default is 1)
    --endcount=<count>              Specify the last test case's job count,
                                    rouneded to the last power of 2
                                    (default is 1)
    --help                          Print short usage.
    --man                           Print long usage.

=head1 OPTIONS

=over 8

=item B<--host>

Specify the host of the running MHE to test against.  This option will default
to the hostname of the current machine.

=item B<--port>

Specify the port of the running MHE to test against.  This options will default
to "8080".

=item B<--type>

Specify the factory type to test against.  Usual values are "Fork", "Pbs", "Lsf"
, and "CondorIntelLinux".  This options defaults to "Fork".

=item B<--startcount>

Specify the first test case's job count (default is 1).  The job count is the
number of jobs to run in parallel.  Test cases will be run starting with the
startcount and ending with endcount with endcount by powers of 2.  For example,
if one specifies -startcount=4 and -endcount=40, test cases will be run with job
counts of 4, 8, 16, and 32.

=item B<--endcount>

Specify the last test case's job count, rounded to the last power of 2 (default
is 1).  The job count is the number of jobs to run in parallel.  Test cases will
be run starting with the startcount and ending with endcount with endcount by
powers of 2.  For example, if one specifies -startcount=4 and -endcount=40, test
cases will be run with job counts of 4, 8, 16, and 32.

=item B<--help>

Print short usage.

=item B<--man>

Print long usage.

=cut
