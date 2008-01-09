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
