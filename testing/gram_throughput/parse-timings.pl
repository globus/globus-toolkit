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
        } elsif (($tag eq "complete")) {
            $completeTimings{$thread} = $time;
        }
    }
}
print "<html><body>\n";
print "<table border=1>\n";
print "<th> Thread </th> <th> createService </th> <th> start </th> "
      . "<th> complete\n";
my @unsortedKeys = keys(%createServiceTimings);
my @keys = sort { (my $da = $a) =~ s/Thread-//;
                  $da =~ s/main/-1/;
                  (my $db = $b) =~ s/Thread-//;
                  $db =~ s/main/-1/;
                  scalar($da) <=> scalar($db) }
                  @unsortedKeys;
foreach my $key (@keys) {
    my $createServiceTiming = $createServiceTimings{$key};
    my $startTiming = $startTimings{$key};
    my $completeTiming = $completeTimings{$key};
    print "<tr> <td>" . $key . "</td> <td>"
          .  $createServiceTiming . " ms</td> <td>" . $startTiming;
    #if ($completeTiming ne "") {
        print " ms</td> <td>" . $completeTiming;
    #} else {
    #    print " ms</td> <td>" . $completeTimings{"main"};
    #}
    print " ms</td> </tr>\n";
}
close FILE;
print "</table>\n</body></html>\n";
