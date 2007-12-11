#! /usr/bin/env perl

# 
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


use strict;
use Test::Harness;
use Cwd;
use Getopt::Long;
require 5.005;
use File::Temp qw/ tempfile tempdir /;

push(@INC, $ENV{GLOBUS_LOCATION} . "/test/globus_gridftp_server_test");

require "gfs_common.pl";

my @tests;
my @todo;

my $globus_location = $ENV{GLOBUS_LOCATION};

#$Test::Harness::verbose = 1;

my $runserver;
my $runwuserver;
my $nogsi;
my $server_pid;
my $server_cs;
my $subject;

GetOptions('nogsi' => \$nogsi);


my @dc_opts;

my @proto;

if(defined($nogsi))
{
    push(@dc_opts, "");
    push(@proto, "ftp://");
}
else
{
    $subject = gfs_setup_security_env();

    push(@dc_opts, "-subject \"$subject\"");

    push(@proto, "gsiftp://");
}

my @concur;
push(@concur, "");
for(my $i = 1; $i < 20; $i += 3)
{
    push(@concur, "-cc $i");
}
# tests here
#$server_pid,$server_cs = gfs_setup_server_basic();
# setup dirs
my $work_dir = tempdir( CLEANUP => 1);
mkdir("$work_dir/GL");

print "Setting up source transfer dir\n";
system("cp -rL $globus_location/include/* $work_dir/GL/ >/dev/null 2>&1");

print "Make empty files and directories\n";
mkdir("$work_dir/GL/EMPTY");
system("touch $work_dir/GL/file_mt");

system("dd if=/dev/urandom of=$work_dir/src.data count=10 bs=1024 >/dev/null 2>&1");

for(my $i = 1; $i <= 10; $i++)
{
    mkdir("$work_dir/GL/$i");
    for(my $j = 1; $j <= $i; $j++)
    {
        system("cp $work_dir/src.data $work_dir/GL/$i/$j");
    }
}

my $test_ndx = 0;
my $cnt=0;
($server_pid, $server_cs, $test_ndx) = gfs_next_test($test_ndx);
while($test_ndx != -1)
{
    print "Server config $test_ndx\n";

    foreach(@proto)
    {
        my $p=$_;
        my $server_port = $server_cs;
        $server_port =~ s/.*://;
        my $dst_url = "$p"."127.0.0.1:$server_port"."$work_dir/GL2/";
        my $src_url = "$p"."localhost:$server_port"."$work_dir/GL/";

        foreach(@dc_opts)
        {
            my $dc_opt=$_;

            foreach(@concur)
            {
                my $cc=$_;
                my $cmd = "globus-url-copy $cc $dc_opt -cd -r $src_url $dst_url";

                &run_guc_test($cmd);
                system("rm -rf $work_dir/GL2/");
                $cnt++;
            }
        }
    }
    ($server_pid, $server_cs, $test_ndx) = gfs_next_test($test_ndx);
}



sub run_guc_test()
{
    my $cmd = shift;
        print "$cmd\n";
        my $rc = system($cmd);
        if($rc != 0)
        {
            gfs_cleanup();
            print "ERROR\n";
            exit 1;
        }
        print "Transfer successful, checking results...\n";
        $rc = system("diff -r $work_dir/GL/ $work_dir/GL2/");
        if($rc != 0)
        {
            gfs_cleanup();
            print "ERROR\n";
            exit 1;
        }
}
