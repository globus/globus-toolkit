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
&run_lsf_seg("$testtmp/output");

ok(compare("$testtmp/output", "$testtmp/output.expected") == 0);

sub run_lsf_seg
{
    my $output = shift;
    my $seg = $ENV{GLOBUS_LOCATION} .
        '/libexec/globus-scheduler-event-generator';
    my @args = ($seg, '-s', 'lsf', '-t', $start);
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

    open(LOG, ">>$path");
    print LOG "#3\n";
    close(LOG);

    my $last_sleep = 0;
    foreach (@test_data) {
        my $state;
        my $datestring;
        my $event;
        my $user;
        my $logfile;
        my $exit = 0;
        ($sleep, $jobid, $type) = ($_->[0], $_->[1], $_->[2]);

        #sleep($sleep - $last_sleep);
        $last_sleep = $sleep;

        $datestring = $start + $sleep;
        $user = (getpwuid($<))[0];
        $host = (POSIX::uname)[1];
        if ($type =~ m/pending/) {
            $state = 1;
            $event = "\"JOB_NEW\" \"6.0\" $datestring $jobid 292 0 1 $start 0 0 0 0 0 $me 0 0 0 0 0 0 0 0 0 0 0 \"\" 1.0 0 \"normal\" \"\" localhost \"/\" \"/\" \"\" \"\" \"\" \"/home/me\" \"\" 1 \"\" \"\" \"\" $datestring \"jobmane.$jobid\" \"/bin/true\" 0 \"\" \"me\@localhost\" \"project\" 0 1 \"\" \"\" \"\" 0 0 \"\" \"\" \"\" 0 \"\" \"\" \"\" \"\" \"\" 0\n"
        } elsif ($type =~ m/active/) {
            $state = 2;
            $event = "\"JOB_START\" \"6.0\" $datestring $jobid 4 $$ $$ 1.0 1 \"localhost\" \"\" \"\" 0 \"\" 0 \"\"\n";
        } elsif ($type =~ m/done/) {
            $state = 8;
            $event = "\"JOB_STATUS\" \"6.0\" $datestring $jobid 32 0 0 0.4 $datestring 0 \"\" 0 0 0\n";
        } elsif ($type =~ m/failed/) {
            $state = 4;
            $event = "\"JOB_STATUS\" \"6.0\" $datestring $jobid 32 0 0 0.4 $datestring 0 \"\" 0 0 14\n";
            $exit = 14;
        }
        open(LOG, ">>$path");
        print LOG $event;
        close(LOG);

        open(LOG, ">>$testtmp/output.expected");
        printf LOG "%03d;%d;%d;%d;%d\n", 1, $start + $sleep,
                $jobid, $state, $exit;
        close(LOG);
    }
}

sub get_log_path {
    my $gram_lsf_conf = $ENV{GLOBUS_LOCATION} . "/etc/globus-lsf.conf";
    open(CONF, "<$gram_lsf_conf");
    my $log;

    while (<CONF>) {
        chomp;
        my ($var, $val) = split(/\s*=\s*/, $_);
        if ($var =~ m/^log_path$/) {
            $log = $val;
        }
    }
    close(CONF);

    $log .= '/lsb.events';

    return $log;
}

sub make_tmpdir
{
    my $root;
    my $suffix = '/seg_lsf_test';
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
        #File::Path::rmtree($testtmp);
    }
}

