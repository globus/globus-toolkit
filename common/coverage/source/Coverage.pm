package Globus::Coverage;

use strict;
use Carp;


sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $name = shift;
    my $self = {};
    
    bless $self, $class;

    if (defined($name))
    {
        $self->name($name);
    }

    return $self;
}

sub name
{
    my $self = shift;
    my $name = shift;

    if (defined $name)
    {
        $self->{NAME} = $name;
    }
    return $self->{NAME};
}

sub percentage
{
    my $self = shift;
    my $all = shift;
    my $part = shift;

    if ($part > $all) {
        confess("part=$part, all=$all\n");
    }
    if ($all == 0)
    {
        return 100;
    }
    else
    {
        return 100.0 * $part / $all;
    }
}

1;
