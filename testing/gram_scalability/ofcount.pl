#! /usr/bin/perl

use strict;
use IO::Handle;

my $verbose=0;
if ( "$ARGV[0]" eq "-v" ) {
    $verbose=1;
    print "Verbose Output...\n";
    if ("$ARGV[1]" eq "-v") {
        $verbose=2;
    }
}

my $some_pid="26581";
my $lsof_cmd="/usr/sbin/lsof";
my $username="lane";

STDOUT->autoflush(1);

#lsof_list=`$lsof_cmd -p $some_pid -Ff | grep -e "f[0-9][0-9]*" | sed "s/^f//g"`
#lsof_list=`$lsof_cmd -u $username -a -c java -Ff | grep -e "f[0-9][0-9]*" | sed "s/^f//g"`
#my @lsof_list=`$lsof_cmd -u $username -Ff | grep -e "f[0-9][0-9]*" | sed "s/^f//g"`;
my @lsof_list=`$lsof_cmd -u $username`;
my %entries_data;
for my $lsof_fd (@lsof_list) {
    #columns are...
    #COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME or
    #COMMAND PID USER FD TYPE DEVICE NODE NAME (for FIFO)
    if (   ($lsof_fd =~ /COMMAND/)
        or ($lsof_fd =~ /MEM/)
        or ($lsof_fd =~ /DIR/)
        or ($lsof_fd =~ /CHAR/)
       ) {
        next;
    }
    my @entry_data = split(' ', $lsof_fd);
    #if ("X%entries_data->{$entry_data[3]}" eq "X") {
    if (!defined %entries_data->{$entry_data[3]}) {
        %entries_data->{$entry_data[3]}
            = "$entry_data[4] $entry_data[6] $entry_data[7] $entry_data[8]"
            . ":$entry_data[1]";
        if ($verbose gt 1) {
            print keys(%entries_data) . "\n";
        }
    } else {
        if (%entries_data->{$entry_data[3]} =~ /[:,]$entry_data[1]/) {
            next;
        }
        %entries_data->{$entry_data[3]}
            = %entries_data->{$entry_data[3]} . ",$entry_data[1]";
    }
}
if ($verbose gt 0) {
    my $key;
    my $value;
    while (($key, $value) = each(%entries_data)) {
        print "$key ==> $value\n";
    }
}

print keys(%entries_data) . "\n";
