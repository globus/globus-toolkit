#! /usr/bin/perl

use IO::File;
use File::Path;
use File::Compare;
use POSIX;
use Test;

my $start = time();
my $testtmp = &make_tmpdir();
my @log_data;
my $log_path = &get_log_path();

@test_data = &parse_test_data();

plan tests => 1;

&write_test_data_to_log($log_path, @test_data);
&run_pbs_seg("$testtmp/output");

ok(compare("$testtmp/output", "$testtmp/output.expected") == 0);

sub run_pbs_seg
{
    my $output = shift;
    my $seg = $ENV{GLOBUS_LOCATION} .
        '/libexec/globus-scheduler-event-generator';
    my @args = ($seg, '-s', $ENV{GLOBUS_LOCATION} .
            '/lib/libglobus_seg_pbs_gcc32dbg.so', '-t', $start);
    my $pid2 = open(FH, "|-");
    my $size;

    if ($pid2 == 0)
    {
        open(STDOUT, ">$output");
        open(STDERR, '>/dev/null');
        exec {$args[0]} @args;
    }

    do
    {
        $size = -s $output;
        sleep(5);
    } while ($size < (-s $output));

    close(FH);
}

sub parse_test_data 
{
    my @result;
    local *IN;

    open(IN, "<test-data.txt");

    while (<IN>) {
        my $state;
        chomp;

        ($sleep, $jobid, $type) = split(/;/, $_);

        push (@result, [$sleep, $jobid, $type]);
    }
    return @result;
}

sub write_test_data_to_log {
    my $path = shift;
    truncate($path, 0);

    my $last_sleep = 0;
    foreach (@test_data) {
        my $state;
        my @date;
        my $datestring;
        my $event;
        my $user;
        my $logfile;
        ($sleep, $jobid, $type) = ($_->[0], $_->[1], $_->[2]);

        #sleep($sleep - $last_sleep);
        $last_sleep = $sleep;

        @date = localtime($start + $sleep);
        $datestring = sprintf("%02d/%02d/%04d %02d:%02d:%02d",
                $date[4]+1, $date[3], $date[5]+1900,
                $date[2], $date[1], $date[0]);
        $user = (getpwuid($<))[0];
        $host = (POSIX::uname)[1];
        if ($type =~ m/pending/) {
            $state = 1;
            $event = "$datestring;0008;PBS_Server;Job;$jobid.$host;".
                    "Job Queued at request of $user\@$host, owner=$user\@host,".
                    " job name = STDIN queue = workq\n";
        } elsif ($type =~ m/active/) {
            $state = 2;
            $event = "$datestring;0008;PBS_Server;Job;$jobid.$host;".
                    "Job Run at request of Scheduler\@$host\n";
        } elsif ($type =~ m/done/) {
            $state = 8;
            $event = "$datestring;0010;PBS_Server;Job;$jobid.$host;".
                    "Exit_status=0 resources_used.cput=00:00:00 ".
                    "resources_used.mem=2743kb resources_used.vmem=1384kb ".
                    "resources_used.walltime=00:00:32\n";
        } elsif ($type =~ m/failed/) {
            $state = 4;
            $event = "$datestring;0008;PBS_Server;Job;$jobid.$host;".
                    "Job deleted at request of $user\@$host\n";
        }
        open(LOG, ">>$path");
        print LOG $event;
        close(LOG);

        open(LOG, ">>$testtmp/output.expected");
        printf LOG "%03d;%d;%d.$host;%d;%d\n", 1, $start + $sleep,
                $jobid, $state, 0;
        close(LOG);
    }
}

sub get_log_path {
    my $gram_pbs_conf = $ENV{GLOBUS_LOCATION} . "/etc/globus-pbs.conf";
    open(CONF, "<$gram_pbs_conf");
    my $log;
    my @date;

    while (<CONF>) {
        chomp;
        my ($var, $val) = split(/\s*=\s*/, $_);
        if ($var =~ m/^log_path$/) {
            $log = $val;
        }
    }
    close(CONF);

    @date = localtime($start);
    $log .= sprintf("/%04d%02d%02d", $date[5]+1900, $date[4]+1, $date[3]);

    return $log;
}

sub make_tmpdir
{
    my $root;
    my $suffix = '/seg_pbs_test';
    my $created = 0;
    my $tmpname;
    my @acceptable = split(//, "abcdefghijklmnopqrstuvwxyz".
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
                               "0123456789");
    if(exists($ENV{TMPDIR}))
    {
        $root = $ENV{TMPDIR};
    }
    else
    {
        $root = '/tmp';
    }
    while($created == 0)
    {
        $tmpname = $root . $suffix .
                   $acceptable[rand() * $#acceptable] .
                   $acceptable[rand() * $#acceptable] .
                   $acceptable[rand() * $#acceptable] .
                   $acceptable[rand() * $#acceptable] .
                   $acceptable[rand() * $#acceptable] .
                   $acceptable[rand() * $#acceptable];
        $created = mkdir($tmpname, 0700);
        if($created)
        {
            if(-l $tmpname or ! -d $tmpname or ! -o $tmpname)
            {
                $created = 0;
            }
        }
    }
    return $tmpname;
}

END
{
    if(-d $testtmp and -o $testtmp)
    {
        File::Path::rmtree($testtmp);
    }
}

