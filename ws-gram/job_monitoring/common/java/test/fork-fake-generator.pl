#! /usr/bin/perl

use IO::File;
use File::Path;
use File::Compare;

my $start = time();
my @log_data;
my $log_path = &get_log_path();

$|=1;

@test_data = &parse_test_data();

&write_test_data_to_log($log_path, @test_data);

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

        sleep($sleep - $last_sleep);
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
        close(LOG);
        printf ("%ld;%ld;%s\n", $start+$sleep, $jobid, $type);
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
