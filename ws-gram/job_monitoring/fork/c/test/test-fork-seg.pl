#! /usr/bin/perl

use IO::File;
use File::Path;
use File::Compare;

my $start = time();
my $testtmp = &make_tmpdir();
my @log_data;
my $log_path = &get_log_path();

@test_data = &parse_test_data();

&write_test_data_to_log($log_path, @test_data);
&run_fork_seg("$testtmp/output");

if (compare("$testtmp/output", $log_path) == 0)
{
    print "ok\n";
}
else
{
    print "not ok\n";
}

sub run_fork_seg
{
    my $output = shift;
    my $seg = $ENV{GLOBUS_LOCATION} .
        '/libexec/globus-scheduler-event-generator';
    my @args = ($seg, '-s', $ENV{GLOBUS_LOCATION} .
            '/lib/libglobus_seg_fork_gcc32dbg.so', '-t', $start);
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

        ($sleep, $jobid, $type) = ($_->[0], $_->[1], $_->[2]);

        #sleep($sleep - $last_sleep);
        $last_sleep = $sleep;
        if ($type =~ m/pending/) {
            $state = 1;
        } elsif ($type =~ m/active/) {
            $state = 2;
        } elsif ($type =~ m/done/) {
            $state = 8;
        } elsif ($type =~ m/failed/) {
            $state = 4;
        }
        open(LOG, ">>$path");
        printf LOG "001;%d;$jobid;$state;0\n", $start + $sleep;
        close(LOG)
    }
}

sub get_log_path {
    my $gram_fork_conf = $ENV{GLOBUS_LOCATION} . "/etc/globus-fork.conf";
    open(CONF, "<$gram_fork_conf");
    my $log;

    while (<CONF>) {
        chomp;
        my ($var, $val) = split(/\s*=\s*/, $_);
        if ($var =~ m/^log_path$/) {
            $log = $val;
        }
    }
    close(CONF);

    return $log;
}

sub make_tmpdir
{
    my $root;
    my $suffix = '/seg_fork_test';
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

