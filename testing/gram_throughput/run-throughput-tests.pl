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

=item B<--help>

Print short usage.

=item B<--man>

Print long usage.

=cut
