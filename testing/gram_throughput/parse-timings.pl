#!/usr/bin/perl

use strict;
use IO::Handle;

my $file=$ARGV[0];

STDOUT->autoflush(1);

my %createServiceTimings;
my %startTimings;
my %completeTimings;

open FILE, "$file" or die "Error: unable to open file ".$file." for reading";
while (<FILE>) {
    if (/\]\[main\]\[[0-9]+/ or /\]\[Thread-[0-9]+\]\[[0-9]+/) {
        s/^..* - \[/\[/;
        s/\]\[/\|/g;
        s/[\[\]]//g;
        s/[ \n]+//g;
        my ($tag, $thread, $time) = split '\|';
        #print "Tag: " . $tag . "\n";
        #print "Thread: " . $thread . "\n";
        #print "Time: " . $time . "\n";
        if ($tag eq "createService") {
            $createServiceTimings{$thread} = $time;
        } elsif ($tag eq "start") {
            $startTimings{$thread} = $time;
        } elsif (   $tag eq "complete"
                   or $tag eq "Done" or $tag eq "Failed") {
            $completeTimings{$thread} = $time;
        }
    }
}
print "Thread\t\tcreateService\tstart\tcomplete\n";
my @keys = keys(%createServiceTimings);
foreach my $key (@keys) {
    my $createServiceTiming = $createServiceTimings{$key};
    my $startTiming = $startTimings{$key};
    my $completeTiming = $completeTimings{$key};
    print   $key . "\t";
    if ($key eq "main") { print "\t"; }
    print $createServiceTiming . "\t\t" . $startTiming;
    if ($completeTiming ne "") {
        print "\t" . $completeTiming;
    } else {
        print "\t" . $completeTimings{"main"};
    }
    print "\n";
}
close FILE;
