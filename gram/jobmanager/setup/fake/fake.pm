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
#
# Globus::GRAM::JobManager::fake package
#

use Config;
use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobManager;

# NOTE: This package name must match the name of the .pm file!!
package Globus::GRAM::JobManager::fake;

@ISA = qw(Globus::GRAM::JobManager);

sub new {

    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    return $self;
}

# Create a file in the new jobs directory.
# The Fake LRM will pick it up and process it
sub submit {

    my $self = shift;
    my $config = read_configuration();
    my $job_id = generate_job_id();
    open(FH, ">$config->{new_jobs_dir}/$job_id");
    close(FH);
    return { JOB_STATE => Globus::GRAM::JobState::PENDING,
             JOB_ID => $job_id };
}

# Check for existence of a job file in the pending and active
# job directory. If it does not exist there we assume that
# the job is done
sub poll {

    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();
    my $config = read_configuration();
    my $state;
    
    if (-e "$config->{pending_jobs_dir}/$job_id") {
        $state = Globus::GRAM::JobState::PENDING;
    } elsif (-e "$config->{active_jobs_dir}/$job_id") {
        $state = Globus::GRAM::JobState::ACTIVE;
    } else {
        $state = Globus::GRAM::JobState::DONE;
    }
    
    return {JOB_STATE => $state};
}

# Create a file in the cancelled jobs directory.
# The Fake LRM will pick it up and process it
sub cancel {

    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();
    my $config = read_configuration();
    open(FH, ">$config->{cancelled_jobs_dir}/$job_id");
    close(FH);
    return { JOB_STATE => Globus::GRAM::JobState::FAILED };    
}

# read configuration from ${GLOBUS_LOCATION}/etc/globus-fake.conf
sub read_configuration {

    my %config = ();
    my $globus_fake_conf = "$ENV{GLOBUS_LOCATION}/etc/globus-fake.conf";
    if (-r $globus_fake_conf) {
        local(*FH);
        if (open(FH, "<$globus_fake_conf")) {
            while(<FH>) {
                chomp;
                if (m/(.*)=(.*)$/) {
                    $config{$1} = $2;
                }
            }
            close(FH);
        }
    }
    return \%config;
}

# Generate a random job id
sub generate_job_id {

    my $length = 12; 
    my @chars = ('0'..'9','a'..'f');
    my $id = "fake_";
    foreach (1..$length) {
        $id .= $chars[rand @chars];
    }
    return $id;
}

1;
