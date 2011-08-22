# Copyright 1999-2010 University of Chicago
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
# 

use Globus::Core::Paths;

package Globus::Core::Config;

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = {};
    my $path = shift;
    my $fh;
    my $line;

    $path = Globus::Core::Paths::eval_path($path);

    if (! -f $path)
    {
        return undef;
    }

    open($fh, "<$path");

    # Odd parsing algorithm lifted from C code. See globus_common_paths.c
    while ($line = <$fh>)
    {
        # Remove leading whitespace
        $line =~ s/^[ \t]*//;

        # Process anything that's an attr=.* line
        if ($line =~ m/([^=]*)=(.*)/)
        {
            my $attr = $1;
            my $value = $2;

            # Remove single leading double quote if present
            $value =~ s/^"//;
            # Remove all trailing space, tab, newline and quotes
            $value =~ s/[ \t"]*$//;
            $self->{$attr} = $value;
        }
    }
    bless $self, $class;

    return $self;
}

sub get_attribute
{
    my $self = shift;
    my $attribute = shift;

    if (exists $self->{$attribute})
    {
        return $self->{$attribute};
    }
    else
    {
        return undef;
    }
}

1;
