package Globus::Coverage::Function;

use strict;
use Carp;
use Globus::Coverage;

@Globus::Coverage::Function::ISA = qw(Globus::Coverage);

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    
    bless $self, $class;

    return $self;
}

sub statement_coverage
{
    my $self = shift;
    my $statements = shift;
    my $statements_reached = shift;
    my $coverage = [0, 0];

    if (defined($statements) && defined($statements_reached)) {
        $self->{STATEMENTS} = $statements;
        $self->{STATEMENTS_REACHED} = $statements_reached;
    }
    $coverage->[0] = $self->{STATEMENTS};
    $coverage->[1] = $self->{STATEMENTS_REACHED};
    $coverage->[2] = $self->percentage($coverage->[0], $coverage->[1]);

    return $coverage;
}

sub branch_coverage
{
    my $self = shift;
    my $branches = shift;
    my $branches_reached = shift;
    my $coverage = [0, 0];

    if (defined($branches) && defined($branches_reached)) {
        $self->{BRANCHES} = $branches;
        $self->{BRANCHES_REACHED} = $branches_reached;
    }
    $coverage->[0] = $self->{BRANCHES};
    $coverage->[1] = $self->{BRANCHES_REACHED};
    $coverage->[2] = $self->percentage($coverage->[0], $coverage->[1]);

    return $coverage;
}

1;
