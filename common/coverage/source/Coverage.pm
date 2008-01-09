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
