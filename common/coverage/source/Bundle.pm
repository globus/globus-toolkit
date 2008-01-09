# Copyright 1999-2008 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package Globus::Coverage::Bundle;

use strict;
use Globus::Coverage;

@Globus::Coverage::Bundle::ISA = qw(Globus::Coverage);

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    
    bless $self, $class;

    return $self;
}

sub package
{
    my $self = shift;
    my $package_name = shift;
    my $package_info = shift;

    if (defined($package_info))
    {
        $self->{PACKAGES}->{$package_name} = $package_info;
    }
    return $self->{PACKAGES}->{$package_name};
}

sub package_names
{
    my $self = shift;

    return keys %{$self->{PACKAGES}};
}

sub statement_coverage
{
    my $self = shift;
    my $statements = [0,0];

    foreach my $pkgname ($self->package_names()) {
        my $pkginfo = $self->package($pkgname);
        my $coverage = $pkginfo->statement_coverage();
        $statements->[0] += $coverage->[0];
        $statements->[1] += $coverage->[1];
    }

    $statements->[2] = $self->percentage($statements->[0], $statements->[1]);

    return $statements;
}

sub function_coverage
{
    my $self = shift;
    my $functions = [0,0];

    foreach my $pkgname ($self->package_names()) {
        my $pkginfo = $self->package($pkgname);
        my $coverage = $pkginfo->function_coverage();
        $functions->[0] += $coverage->[0];
        $functions->[1] += $coverage->[1];
    }

    $functions->[2] = $self->percentage($functions->[0], $functions->[1]);

    return $functions;
}

sub branch_coverage
{
    my $self = shift;
    my $branches = [0,0];

    foreach my $pkgname ($self->package_names()) {
        my $pkginfo = $self->package($pkgname);
        my $coverage = $pkginfo->branch_coverage();
        $branches->[0] += $coverage->[0];
        $branches->[1] += $coverage->[1];
    }

    $branches->[2] = $self->percentage($branches->[0], $branches->[1]);

    return $branches;
}

1;
