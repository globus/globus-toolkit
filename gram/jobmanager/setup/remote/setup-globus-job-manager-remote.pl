#! /usr/bin/env perl

# Copyright 1999-2006 University of Chicago
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

BEGIN
{
    use POSIX qw(getcwd);

    if (! exists($ENV{GLOBUS_LOCATION}))
    {
        my $p = $0;

        if ($p !~ m/^\//)
        {
            $p = getcwd() . '/' . $p;
        }

        my @p = split(/\//, $p);

        $ENV{GLOBUS_LOCATION} = join('/', @p[0..$#p-2]);

    }
    push(@INC, "$ENV{GLOBUS_LOCATION}/lib/perl");

    if (exists $ENV{GPT_LOCATION})
    {
        push(@INC, "$ENV{GPT_LOCATION}/lib/perl");
    }
}

require Grid::GPT::Setup;
use Getopt::Long;
use strict;

my $name		= 'jobmanager-remote';
my $host;
my $type;
my $location;
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'host|h=s'  => \$host,
	   'type|t=s' => \$type,
	   'location|l=s' => \$location,
	   'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_remote");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

if($host eq "" || $type eq "" || $location eq "")
{
    &usage;
}

# Do script relocation
print `./find-remote-tools --with-host=$host --with-location=$location --with-manager=$type`;
if($? != 0)
{
    print STDERR "Error locating remote commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m remote -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");

if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

sub usage
{
    print "Usage: $0 [options] -host=HOST -type=TYPE -location=LOCATION\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--help|-h]\n";
    exit 1;
}
