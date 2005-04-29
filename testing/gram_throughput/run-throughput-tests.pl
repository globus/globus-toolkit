#!/usr/bin/perl

use strict;
use IO::Handle;
use Getopt::Long;
use Pod::Usage;

my $hostname = `$ENV{GLOBUS_LOCATION}/libexec/globus-libc-hostname`;

my ($verbose,   $host,  $port,  $startLoad,    $endLoad) =
   (1,          "",     8080,   1,             1);
my ($parallelism,   $duration,  $factoryType,   $help,  $man) =
   (1,              0,          "Fork",         0,      0);

GetOptions(
    "verbose!"      => \$verbose,
    "h|host=s"      => \$host,
    "p|port=s"        => \$port,
    "startLoad=s"   => \$startLoad,
    "endLoad=s"     => \$endLoad,
    "l|parallelism=s" => \$parallelism,
    "duration=s"    => \$duration,
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
          . "Start Load: $startLoad\n"
          . "End Load: $endLoad\n"
          . "Parallelism: $parallelism\n"
          . "Duration: $duration\n";
}

STDOUT->autoflush(1);
TESTLOG->autoflush(1);
#TIMINGSLOG->autoflush(1);

for (my $index=$startLoad; $index<=$endLoad; $index*=2) {
    my $testOutputFile = "throughput-test-" . $index . ".log";
    my $testExec = "ant "
                 . "-Dservice.host=$host "
                 . "-Dservice.port=$port "
                 . "-Dload=$index "
                 . "-Dparallelism=$parallelism "
                 . "-Dduration=$duration "
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

    #my $timingsOutputFile = "throughput-timings-" . $index . ".html";
    #my $timingsExec = "./parse-timings.pl " . $testOutputFile;

    #open TIMINGSLOG, ">$timingsOutputFile" or die "Error: unable to open file "
        #. $timingsOutputFile . "for writing";
    #open EXEC, "$timingsExec |" or die "Error: unable to execute command \'"
        #. $timingsExec . "\'";
        #while (<EXEC>) {
            #if ($verbose) {
                #print;
            #}
            #print TIMINGSLOG;
        #}
    #close EXEC;
    #close TIMINGSLOG;
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
    --startload=<load>              Specify the first test case's per-client
                                    job load (default is 1)
    --endload=<load>                Specify the last test case's per-client
                                    job count, rouneded to the last power
                                    of 2 (default is 1)
    --parallelism=<parallelism>     Specify the number of client threads
                                    (NOT CURRENTLY SUPPORTED)
    --duration=<duration>           Specify the duration of each test case in
                                    milliseconds.
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

=item B<--startload>

Specify the first test case's per-client job count (default is 1).
The job load is number of jobs to maintain at the service for each client
thread.  Test cases will be run starting with startload and ending with endload 
by powers of 2.  For example, if one specifies -startload=4 and -endload=40,
test cases will be run with job loads of 4, 8, 16, and 32.

=item B<--endcount>

Specify the first test case's per-client job count, rounded to the last power of
2 (default is 1).
The job load is number of jobs to maintain at the service for each client
thread.  Test cases will be run starting with startload and ending with endload 
by powers of 2.  For example, if one specifies -startload=4 and -endload=40,
test cases will be run with job loads of 4, 8, 16, and 32.

=item B<--parallelism>

Specify the number of client threads.  Each client thread will be required to
maintain the current test case's job load for the duration specified with the
duration options.

=item B<--duration>

Specify the duration of each test case (NOT CURRENTLY SUPPORTED).  The duration
is the length of time each client thread is to continue to maintain the current
test case's job load.

=item B<--type>

Specify the factory type that jobs are submitted to.  The factory type
represents the type of queue scheduler that the factory (MMJFS) is associated
with.  Commone values are "Fork", "Pbs", "Lsf", and "CondorIntelLinux" (default
is "Fork").


=item B<--help>

Print short usage.

=item B<--man>

Print long usage.

=cut
