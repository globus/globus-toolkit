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


use Grid::GPT::Setup;
use Getopt::Long;
use strict;

my $name		= 'jobmanager-condor';
my $manager_type	= 'condor';
my $condor_os		= '';
my $condor_arch		= '';
my $vanilla_check       = 0;
my $c_opts		= '';
my $mpi_script          = '';
my $help                = 0;
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'help|h' => \$help,
	   'condor-os=s' => \$condor_os,
	   'condor-arch=s' => \$condor_arch,
           'vanilla-check' => \$vanilla_check,
           'mpi-script=s' => \$mpi_script);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_condor");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
my $setupdir    = "$globusdir/setup/globus";

mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager", 0777;

chdir $setupdir;

if($condor_os ne '')
{
    $c_opts = " --with-condor-os=$condor_os";
}
if($condor_arch ne '')
{
    $c_opts .= " --with-condor-arch=$condor_arch";
}
if ($vanilla_check)
{
    $c_opts .= " --with-check-vanilla-files";
}
if ($mpi_script ne '')
{
    $c_opts .= " --with-mpi-script=$mpi_script";
}

print `./find-condor-tools $c_opts --cache-file=/dev/null`;
if($? != 0)
{
    print STDERR "Error locating condor commands, aborting!\n";
    exit 2;
}

chmod 0755, './globus-condor-print-config';

my $condor_jm_config = `./globus-condor-print-config`;
chomp($condor_jm_config);

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m condor -s \"$name\"";
system("$cmd -extra-config='$condor_jm_config' >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

open(VALIDATION_FILE, ">$ENV{GLOBUS_LOCATION}/share/globus_gram_job_manager/condor.rvf");

print VALIDATION_FILE <<EOF;
Attribute: condorsubmit
Description: "Allow the client to specify abitrary additional attributes to
             be included in the Condor submit description file."
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT
EOF

close VALIDATION_FILE;

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [-service-name|-s service_name]\n".
	  "          [-condor-os=CONDOR OS]\n".
	  "          [-condor-arch=CONDOR ARCH]\n".
	  "          [-vanilla-check]\n".
	  "          [-mpi-script]\n".
	  "          [-help]\n";
    exit 1;
}
