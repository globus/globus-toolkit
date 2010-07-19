package Util;

use strict;

# remove whitespaces from string
sub trim ($) {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub debug($) {
    my $string = shift;
    print STDOUT "    [DEBUG]: $string\n" if ($ENV{TEST_DEBUG});
}

sub error($) {
    my $string = shift;
    print STDOUT "    [-->ERROR<--]: $string\n";
}

1;
