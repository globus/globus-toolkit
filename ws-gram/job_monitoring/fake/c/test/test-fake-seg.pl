#! /usr/bin/perl

use IO::File;
use File::Path;
use File::Compare;
use Test;

my $start = time();
my $testtmp = &make_tmpdir();
my @log_data;
my $skip_all = 0;
my $gram_fake_conf = $ENV{GLOBUS_LOCATION} . '/etc/globus-fake.conf';
my $gram_fake_conf_save = "${gram_fake_conf}.save";
my $log_path = &get_log_path();

if (! defined($log_path))
{
    $skip_all = 1;
}

plan tests => 1;

skip($skip_all ? "Fake SEG not configured" : 0, &run_test, 0);


sub run_test
{
    if (! $skip_all)
    {
        @test_data = &parse_test_data();
        &write_test_data_to_log($log_path, @test_data);
        my $rc = &run_fake_seg("$testtmp/output");

        if ($rc == 0)
        {
            return compare("$testtmp/output", $log_path);
        }
        else
        {
            return 'Unable to run SEG with fake module: is it installed?';
        }
    }
    else
    {
        return "skip";
    }
}

sub run_fake_seg
{
    my $output = shift;
    my $seg = $ENV{GLOBUS_LOCATION} .
        '/libexec/globus-scheduler-event-generator';
    my @args = ($seg, '-s', 'fake', '-t', $start);
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
    rename($gram_fake_conf, $gram_fake_conf_save);

    open(CONF, "<$gram_fake_conf_save") || return undef;
    open(TMP_CONF, ">$gram_fake_conf") || return undef;
    my $log = "$testtmp/globus-fake.log";

    while (<CONF>) {
        chomp;
        if ($_ ne "" && !($_ =~ m/^#/)) {
            my ($var, $val) = split(/\s*=\s*/, $_);
            if ($var =~ m/^log_path$/) {
                print TMP_CONF "log_path=$log\n";
            } else {
                print TMP_CONF "$_\n";
            }
        }
    }
    close(CONF);
    close(TMP_CONF);

    return $log;
}

sub make_tmpdir
{
    my $root;
    my $suffix = '/seg_fake_test';
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

    if (-f $gram_fake_conf_save)
    {
        rename($gram_fake_conf_save, $gram_fake_conf);
    }
}
