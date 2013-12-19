#! /usr/bin/perl

# generates a sorted list of fake events to be used by various SEG tests
# kept for posterity, a sample test data file is included in the pkg.

my $events;

my $start;
for ($i = 0; $i < 50; $i++) {
    my $r = int(rand(2));

    if ($r == 0) {
        $events->{$start}->{$i} = "pending";
        $start += int(rand(5));
        $events->{$start}->{$i} = "active";
        $start += int(rand(5));
        $events->{$start}->{$i} = "done";
        $start += int(rand(5));
    } elsif ($r == 1) {
        $events->{$start}->{$i} = "pending";
        $start += int(rand(5));
        $events->{$start}->{$i} = "active";
        $start += int(rand(5));
        $events->{$start}->{$i} = "failed";
        $start += int(rand(5));
    } else {
        $events->{$start}->{$i} = "pending";
        $start += int(rand(5));
        $events->{$start}->{$i} = "failed";
        $start += int(rand(5));
    }
}

foreach $stamp (sort {$a <=> $b} keys %{$events}) {
    foreach $id (keys %{$events->{$stamp}}) {
        printf "%05d;$id;$events->{$stamp}->{$id}\n", $stamp;
    }
}

