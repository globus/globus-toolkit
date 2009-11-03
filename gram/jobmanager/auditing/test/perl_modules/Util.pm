package Util;

use strict;

sub new() {

  my $proto = shift;
  my $self={};
  bless($self, $proto);  
  return $self;
}

# remove whitespaces from string
sub trim () {
    my $self = shift;
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub debug() {
    my $self = shift;
    my $string = shift;
    print STDOUT "    [DEBUG]: $string\n";
}

sub error() {
    my $self = shift;
    my $string = shift;
    print STDOUT "    [-->ERROR<--]: $string\n";
}

1;