#!/usr/bin/perl

use strict;
use IO::Handle;

my $file=$ARGV[0];

STDOUT->autoflush(1);

my @maxMemoryValues;
my @totalMemoryValues;
my @freeMemoryValues;

my $largestMax = 0;
open FILE, "$file" or die "Error: unable to open file ".$file." for reading";
while (<FILE>) {
    if (/Max Memory: /) {
        s/..*Max Memory: ([0-9][0-9]*)/$1/;
        @maxMemoryValues = (@maxMemoryValues, $_);
        if ($_ > $largestMax) {
            $largestMax = $_;
        }
        #print "Max Memory: $_";
    } elsif (/Total Memory: /) {
        s/..*Total Memory: ([0-9][0-9]*)/$1/;
        @totalMemoryValues = (@totalMemoryValues, $_);
        #print "Total Memory: $_";
    } elsif (/Free Memory: /) {
        s/..*Free Memory: ([0-9][0-9]*)/$1/;
        @freeMemoryValues = (@freeMemoryValues, $_);
        #print "Free Memory: $_";
    }
}

if ($largestMax eq 0) {
    print "No records.\n";
    exit 0;
}

my $byteStep = 80 / $largestMax;
print "1 Tick = " . (1/$byteStep) . " bytes\n";
print "* -> Max memory JVM wil try to use.\n";
print "> -> Total memory JVM is making available for use "
      . "(partially allocated).\n";
print "# -> Free memory in JVM (unallocated portion of total memory).\n";
my $charCount;
for (my $index=0; $index<$#maxMemoryValues; $index++) {
    $charCount = $maxMemoryValues[$index] * $byteStep;
    for (my $charIndex=0; $charIndex<$charCount; $charIndex++) {
        print "*";
    }
    print "\n";

    $charCount = $totalMemoryValues[$index] * $byteStep;
    for (my $charIndex=0; $charIndex<$charCount; $charIndex++) {
        print ">";
    }
    print "\n";

    $charCount = $freeMemoryValues[$index] * $byteStep;
    for (my $charIndex=0; $charIndex<$charCount; $charIndex++) {
        print "#";
    }
    print "\n";
}

close FILE;
