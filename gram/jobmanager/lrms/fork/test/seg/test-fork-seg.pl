#! /usr/bin/perl

use Globus::Core::Paths;
use Globus::Core::Config;
use IO::File;
use File::Path;
use File::Compare;
use File::Temp qw(tempdir);
use Test::More;
my $testdir = $0;
if ($testdir =~ m|/|)
{
    $testdir =~ s|/+[^/]*$||;
}
else
{
    $testdir = '.';
}

my $start = time();
my $testtmp = tempdir( CLEANUP => 1 );
my @log_data;
my $skip_all = 0;
my $gram_fork_conf = Globus::Core::Paths::eval_path('${sysconfdir}/globus/globus-fork.conf');
my $gram_fork_conf_save = "${gram_fork_conf}.save";
my $config = new Globus::Core::Config($gram_fork_conf);
my $log_path = $config->get_attribute("log_path");

if (! defined($log_path))
{
    plan skip_all => "Fork SEG not configured";
}
else
{
    plan tests => 1;
    ok(run_test() eq '0', "SEG test");
}


sub run_test
{
    if (! $skip_all)
    {
        @test_data = &parse_test_data();
        &write_test_data_to_log($log_path, @test_data);
        my $rc = &run_fork_seg("$testtmp/output");

        if ($rc == 0)
        {
            return compare("$testtmp/output", $log_path);
        }
        else
        {
            return 'Unable to run SEG with fork module: is it installed?';
        }
    }
    else
    {
        return "skip";
    }
}

sub run_fork_seg
{
    my $output = shift;
    my $seg = "$Globus::Core::Paths::sbindir/globus-scheduler-event-generator";
    my @args = ($seg, '-s', 'fork', '-t', $start);
    my $pid2 = open(FH, "|-");
    my $size;

    if ($pid2 == 0)
    {
        open(STDOUT, ">$output");
        open(STDERR, '>/dev/null');
        exec {$args[0]} @args;
    }

    while (! -f $output)
    {
        sleep(1);
    }

    do
    {
        $size = -s $output;
        sleep(5);
    } while ($size < (-s $output));

    close(FH);

    return $?;
}

sub parse_test_data 
{
    my @result;
    local *IN;

    open(IN, "<$testdir/test-fork-seg-data.txt");

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

END
{
    if (-f $gram_fork_conf_save)
    {
        rename($gram_fork_conf_save, $gram_fork_conf);
    }
}
