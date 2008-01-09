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

package Globus::Coverage::Package;

use strict;
use Carp;
use Globus::Coverage::File;

@Globus::Coverage::Package::ISA = qw(Globus::Coverage);

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    
    bless $self, $class;

    return $self;
}

sub file
{
    my $self = shift;
    my $name = shift;
    my $file = shift;

    if (! exists($self->{FILES}->{$name})) {
        if (! defined($file)) {
            $self->{FILES}->{$name} = new Globus::Coverage::File($name);
        } else {
            $self->{FILES}->{$name} = $file;
        }
    }

    return $self->{FILES}->{$name};
}

sub file_names
{
    my $self = shift;
    my $files = shift;

    if (defined($files)) {
        $self->{FILES} = $files;
    }

    return keys %{$self->{FILES}};
}

sub branch_coverage
{
    my $self = shift;
    my $branches = [0,0];

    foreach my $fn ($self->file_names()) {
        my $file = $self->file($fn);
        my $file_branch_coverage = $file->branch_coverage();
        $branches->[0] += $file_branch_coverage->[0];
        $branches->[1] += $file_branch_coverage->[1];
    }
    $branches->[2] = $self->percentage($branches->[0], $branches->[1]);

    return $branches;
}

sub statement_coverage
{
    my $self = shift;
    my $statements = [0,0];

    foreach my $fn ($self->file_names()) {
        my $file = $self->file($fn);
        my $file_statement_coverage = $file->statement_coverage();
        $statements->[0] += $file_statement_coverage->[0];
        $statements->[1] += $file_statement_coverage->[1];
    }
    $statements->[2] = $self->percentage($statements->[0], $statements->[1]);

    return $statements;
}

sub function_coverage
{
    my $self = shift;
    my $functions = [0,0];

    foreach my $fn ($self->file_names()) {
        my $file = $self->file($fn);
        my $file_func_coverage = $file->function_coverage();
        $functions->[0] += $file_func_coverage->[0];
        $functions->[1] += $file_func_coverage->[1];
    }

    $functions->[2] = $self->percentage($functions->[0], $functions->[1]);

    return $functions;
}

1;
