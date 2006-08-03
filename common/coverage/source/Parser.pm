package Globus::Coverage::Parser;

use strict;
use Carp;

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $package_name = shift;
    my $package_dir = shift;
    my $self = {};
    
    bless $self, $class;

    if (defined $package_name) {
        $self->package_name($package_name);
    }
    if (defined $package_dir) {
        $self->package_dir($package_dir);
    }

    return $self;
}

sub package_name
{
    my $self = shift;
    my $package_name = shift;

    if (defined($package_name)) {
        $self->{PACKAGE_NAME} = $package_name;
    }
    return $self->{PACKAGE_NAME};
}

sub package_dir
{
    my $self = shift;
    my $package_dir = shift;

    if (defined($package_dir)) {
        $self->{PACKAGE_DIR} = $package_dir;
    }
    return $self->{PACKAGE_DIR};
}

sub process
{
    Carp::croak("Stub Coverage Parser\n");
}

1;
