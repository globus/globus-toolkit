#! /usr/bin/perl

use IO::File;
use File::Path;
use File::Compare;
use Test;

my $start = time();
my $testtmp = &make_tmpdir();
my @log_data;
my $log_path = &get_log_path();

@test_data = &parse_test_data();

plan tests => 1;

&write_test_data_to_log($log_path, @test_data);
&run_condor_seg("$testtmp/output");

ok(compare("$testtmp/output", "$testtmp/output.expected") == 0);

sub run_condor_seg
{
    my $output = shift;
    my $seg = $ENV{GLOBUS_LOCATION} .
        '/libexec/globus-scheduler-event-generator';
    my @args = ($seg, '-s', $ENV{GLOBUS_LOCATION} .
            '/lib/libglobus_seg_condor_gcc32dbg.so', '-t', $start);
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

        ($sleep, $jobid, $type) = ($_->[0], $_->[1], $_->[2]);

        #sleep($sleep - $last_sleep);
        $last_sleep = $sleep;

        @date = localtime($start + $sleep);
        $datestring = sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
                $date[5]+1900, $date[4]+1, $date[3],
                $date[2], $date[1], $date[0]);
                
        if ($type =~ m/pending/) {
            $state = 1;
            $event = <<EOF;
<c>
    <a n="MyType"><s>SubmitEvent</s></a>
    <a n="EventTypeNumber"><i>0</i></a>
    <a n="EventTime"><s>$datestring</s></a>
    <a n="Cluster"><i>$jobid</i></a>
    <a n="Proc"><i>0</i></a>
    <a n="Subproc"><i>0</i></a>
    <a n="SubmitHost"><s>&lt;127.0.0.1:60644&gt;</s></a>
</c>
EOF
        } elsif ($type =~ m/active/) {
            $state = 2;
            $event = <<EOF;
<c>
    <a n="MyType"><s>ExecuteEvent</s></a>
    <a n="EventTypeNumber"><i>1</i></a>
    <a n="EventTime"><s>$datestring</s></a>
    <a n="Cluster"><i>$jobid</i></a>
    <a n="Proc"><i>0</i></a>
    <a n="Subproc"><i>0</i></a>
    <a n="ExecuteHost"><s>&lt;127.0.0.1:60643&gt;</s></a>
</c>
EOF
        } elsif ($type =~ m/done/) {
            $state = 8;
            $event = <<EOF
<c>
    <a n="MyType"><s>JobTerminatedEvent</s></a>
    <a n="EventTypeNumber"><i>5</i></a>
    <a n="EventTime"><s>$datestring</s></a>
    <a n="Cluster"><i>$jobid</i></a>
    <a n="Proc"><i>0</i></a>
    <a n="Subproc"><i>0</i></a>
    <a n="TerminatedNormally"><b v="t"/></a>
    <a n="ReturnValue"><i>0</i></a>
    <a n="RunLocalUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="RunRemoteUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="TotalLocalUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="TotalRemoteUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="SentBytes"><r>0.000000000000000E+00</r></a>
    <a n="ReceivedBytes"><r>0.000000000000000E+00</r></a>
    <a n="TotalSentBytes"><r>0.000000000000000E+00</r></a>
    <a n="TotalReceivedBytes"><r>0.000000000000000E+00</r></a>
</c>
EOF
        } elsif ($type =~ m/failed/) {
            $state = 4;
            $event = <<EOF
<c>
    <a n="MyType"><s>JobTerminatedEvent</s></a>
    <a n="EventTypeNumber"><i>5</i></a>
    <a n="EventTime"><s>$datestring</s></a>
    <a n="Cluster"><i>$jobid</i></a>
    <a n="Proc"><i>0</i></a>
    <a n="Subproc"><i>0</i></a>
    <a n="TerminatedNormally"><b v="f"/></a>
    <a n="TerminatedBySignal"><i>6</i></a>
    <a n="RunLocalUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="RunRemoteUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="TotalLocalUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="TotalRemoteUsage"><s>Usr 0 00:00:00, Sys 0 00:00:00</s></a>
    <a n="SentBytes"><r>0.000000000000000E+00</r></a>
    <a n="ReceivedBytes"><r>0.000000000000000E+00</r></a>
    <a n="TotalSentBytes"><r>0.000000000000000E+00</r></a>
    <a n="TotalReceivedBytes"><r>0.000000000000000E+00</r></a>
</c>
EOF
        }
        open(LOG, ">>$path");
        print LOG $event;
        close(LOG);

        open(LOG, ">>$testtmp/output.expected");
        printf LOG "%03d;%d;%03d.000.000;%d;%d\n", 1, $start + $sleep,
                $jobid, $state, 0;
        close(LOG);
    }
}

sub get_log_path {
    my $gram_condor_conf = $ENV{GLOBUS_LOCATION} . "/etc/globus-condor.conf";
    open(CONF, "<$gram_condor_conf");
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
    my $suffix = '/seg_condor_test';
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

