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

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script";
}

@INC = (@INC, "$gpath/lib/perl");
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

my $name                = 'jobmanager-pbs';
my $manager_type        = 'pbs';
my $cmd;
my $non_cluster         = 0;
my $cpu_per_node        = 1;
my $remote_shell        = 'default';
my $validate_queues     = 1;
my $softenv_dir         = '';
my $help                = 0;

GetOptions('service-name|s=s' => \$name,
           'non-cluster' => \$non_cluster,
           'cpu-per-node=i' => \$cpu_per_node,
           'remote-shell=s' => \$remote_shell,
           'validate-queues=s' => \$validate_queues,
           'softenv-dir|e=s' => \$softenv_dir,
           'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_pbs");

my $globusdir        = $ENV{GLOBUS_LOCATION};
my $libexecdir        = "$globusdir/libexec";

if($validate_queues ne 'no')
{
   $validate_queues = 1;
}
else
{
   $validate_queues = 0;
}

if($non_cluster != 0)
{
    $non_cluster = "--without-cluster";
}
else
{
    $non_cluster = "--with-cluster";
}

# Do script relocation
mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager", 0777;

my $setupdir = $ENV{GLOBUS_LOCATION} . '/setup/globus';
chdir $setupdir;

print `./find-pbs-tools $non_cluster --with-cpu-per-node=$cpu_per_node --with-remote-shell=$remote_shell --cache-file=/dev/null --with-softenv-dir=$softenv_dir`;
if($? != 0)
{
    print STDERR "Warning: Error locating PBS commands!\n";
    exit 0;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m pbs -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

open(VALIDATION_FILE, ">$ENV{GLOBUS_LOCATION}/share/globus_gram_job_manager/pbs.rvf");    

print VALIDATION_FILE <<EOF;
Attribute: email_address
Description: "Set the email address to receive notifications. See the
             email_on_abort, email_on_execution, and emailontermination attributes."
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: email_on_abort
Description: "Send email to the job submitter (or the address specified in the
             email_address RSL attribute if present) if the job is aborted by the
             scheduler."
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: email_on_execution
Description: "Send email to the job submitter (or the address specified in the
             email_address RSL attribute if present) when the job begins execution."
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: email_on_termination
Description: "Send email to the job submitter (or the address specified in the
             email_address RSL attribute if present) when the job terminates."
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

EOF

if($validate_queues)
{
    # Customize validation file with queue info
    open(QSTAT, "qstat -Q |");

    # discard header
    $_ = <QSTAT>;
    $_ = <QSTAT>;
    my @queues = ();

    while(<QSTAT>)
    {
        chomp;

        $_ =~ m/^(\S+)/;

        push(@queues, $1);
    }

    if(@queues)
    {
        print VALIDATION_FILE "Attribute: queue\n";
        print VALIDATION_FILE join(" ", "Values:", @queues), "\n";
    }
}
close VALIDATION_FILE;


$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--service-name|-s service_name]\n".
          "          [--non-cluster]\n".
          "          [--cpu-per-node=COUNT]\n".
          "          [--remote-shell=rsh|ssh]\n".
          "          [--validate-queues=yes|no]\n".
          "          [--help|-h]\n";
    exit 1;
}
