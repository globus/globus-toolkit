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

my $name		= 'jobmanager-lsf';
my $manager_type	= 'lsf';
my $cmd;
my $validate_queues	= 1;
my $help                = 0;

GetOptions('service-name|s=s' => \$name,
	   'validate-queues=s' => \$validate_queues,
	   'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_lsf");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
my $setupdir    = "$globusdir/setup/globus";

chdir $setupdir;

if($validate_queues ne 'no')
{
   $validate_queues = 1;
}
else
{
   $validate_queues = 0;
}

# Do script relocation
mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager";

$setupdir = $ENV{GLOBUS_LOCATION} . '/setup/globus';

chdir $setupdir;

print `./find-lsf-tools --cache-file=/dev/null`;
if($? != 0)
{
    print STDERR "Error locating LSF commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m lsf -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

if($validate_queues)
{
    open(VALIDATION_FILE,
	 ">$ENV{GLOBUS_LOCATION}/share/globus_gram_job_manager/lsf.rvf");    

    # Customize validation file with queue info
    open(BQUEUES, "bqueues -w |");

    # discard header
    $_ = <BQUEUES>;
    my @queues = ();

    while(<BQUEUES>)
    {
	chomp;

	$_ =~ m/^(\S+)/;

	push(@queues, $1);
    }
    close(BQUEUES);

    if(@queues)
    {
	print VALIDATION_FILE "Attribute: queue\n";
	print VALIDATION_FILE join(" ", "Values:", @queues);

    }
    close VALIDATION_FILE;
}

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--validate-queues=yes|no]\n".
	  "          [--help|-h]\n";
    exit 1;
}
