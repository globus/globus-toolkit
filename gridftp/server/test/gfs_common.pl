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

my $globus_location = $ENV{GLOBUS_LOCATION};
my $server_prog = "$globus_location/sbin/globus-gridftp-server";
my $gfork_prog = "$globus_location/sbin/gfork";
my @cleanup_pids;
my @cleanup_files;
my $gfs_working_dir=$ENV{GLOBUS_LOCATION}."/test/globus_gridftp_server_test";
my $gfs_subject;
my $g_server_args="-disable-usage-stats -no-fork -control-interface 127.0.0.1";

sub gfs_next_test()
{
    my $test_ndx = shift;
    my $pid = -1;
    my $cs = "";

    $test_ndx = $test_ndx + 1;
    gfs_cleanup();

    if($ENV{GRID_FTP_SERVER_CS})
    {
        $cs = $ENV{GRID_FTP_SERVER_CS};
        if($test_ndx == 1)
        {
            return -1,$cs,$test_ndx;
        }
        else
        {
            return -1,$cs,-1;
        }
    }

    if($test_ndx == 1)
    {
        print "Using basic server config\n";
        ($pid,$cs) = gfs_setup_server_basic();
    }
    elsif($test_ndx == 2 && defined($ENV{GLOBUS_TEST_EXTENDED}))
    {
        print "Using single gfork server config\n";
        ($pid,$cs) = gfs_setup_server_fe();
    }
    elsif($test_ndx == 3 && defined($ENV{GLOBUS_TEST_EXTENDED}))
    {
        print "Using gfork split server config\n";
        ($pid,$cs) = gfs_setup_server_split(1);
    }
    elsif($test_ndx == 4 && defined($ENV{GLOBUS_TEST_EXTENDED}))
    {
        print "Using gfork split server 2 stripes\n";
        ($pid,$cs) = gfs_setup_server_split(2);
    }
    elsif($test_ndx == 5 && defined($ENV{GLOBUS_TEST_EXTENDED}))
    {
        print "Using gfork split server 3 stripes\n";
        ($pid,$cs) = gfs_setup_server_split(3);
    }
    else
    {
        $test_ndx = -1;
        print "No more tests.\n";
        return $pid,$cs,$test_ndx;
    }

    print "Setting up src/dst server on $cs\n";

    $cs =~ s/.*:/localhost:/;
    
    $ENV{FTP_TEST_SOURCE_HOST} = $cs;
    $ENV{FTP_TEST_DEST_HOST} = $cs;

    return $pid,$cs,$test_ndx;
}

sub gfs_cleanup()
{
    my $pid;

    kill 2, @cleanup_pids;
    sleep 5;
    kill 9, @cleanup_pids;
    while($#cleanup_files > 0)
    {
        $pid = pop(@cleanup_files);
        close($pid);
    }
}

# run the server in basic mode
sub gfs_setup_server_basic()
{
    my $server_pid;
    my $server_port;
    my $server_host = "localhost";
    my $server_args = " -aa ";
    my $subject;
    my $server_fd;

    my $server_args = "-no-chdir -d 0 ".$server_args." ".$g_server_args;
   
    print "$server_prog $server_args\n"; 
    $server_pid = open($server_fd, "$server_prog $server_args |");
    if($server_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    push(@cleanup_files, $server_fd);

    select((select($server_fd), $| = 1)[0]);
    $server_port = <$server_fd>;
    $server_port =~ s/Server listening at //;
    chomp($server_port);

    if($server_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    
    print "Started server at port $server_port\n";

    $ENV{FTP_TEST_SOURCE_HOST} = "$server_port";
    $ENV{FTP_TEST_DEST_HOST} = "$server_port";   

    sleep 1;

    push(@cleanup_pids, $server_pid);

    return $server_pid, $server_port;
}

sub gfs_setup_security_env()
{
    my $subject;

    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        return;
    }

    if(0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256)
    {
        $ENV{X509_CERT_DIR} = $gfs_working_dir;
        $ENV{X509_USER_PROXY} = $gfs_working_dir . "/testcred.pem";

        my $cmd = "chmod 600 $ENV{X509_USER_PROXY}";
        system($cmd);
    }

    system('chmod go-rw testcred.pem');

    $subject = `grid-proxy-info -identity`;
    chomp($subject);
    $gfs_subject = $subject;
    $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT} = $subject;

    $ENV{GRIDMAP} = $gfs_working_dir . "/gridmap";
    if ( -f $ENV{GRIDMAP})
    {
        system('mv $GRIDMAP $GRIDMAP.old');
    }
    if( 0 != system("grid-mapfile-add-entry -dn \"$subject\" -ln `whoami` -f $ENV{GRIDMAP} >/dev/null 2>&1") / 256)
    {
        print "Unable to create gridmap file\n";
        exit 1;
    }

    return $subject;
}

sub gfs_setup_server_fe()
{
    my $gfork_prog = "$globus_location/sbin/gfork";
    my $gfork_pid;
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt; 
    my $master_gmap;
    my $x;
    my $sec_envs;
    my $use_gsi_opt;
    my $register_args;
    my $server_fd;
    
    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $server_nosec = "-aa";
    }

    my $gfork_single_conf = $gfs_working_dir . "/gfork_single_conf";
    $master_gmap = $ENV{GRIDMAP};

    $sec_envs = "GRIDMAP=$ENV{GRIDMAP}";
    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $sec_envs = "$sec_envs\n  env += X509_CERT_DIR=$ENV{X509_CERT_DIR}";
        $sec_envs = "$sec_envs\n  env += X509_USER_PROXY=$ENV{X509_USER_PROXY}";
        $sec_envs = "$sec_envs\n  env += X509_USER_CERT=$ENV{X509_USER_PROXY}";

        $subject = $gfs_subject;

        $use_gsi_opt = "y";
        $register_args = "-q -G y";
    }
    else
    {
        $register_args = "-q -G n";
        $use_gsi_opt = "n";
    }

    open(IN, "<$gfork_single_conf.in") || die "couldnt open $gfork_single_conf.in";
    open(OUT, ">$gfork_single_conf") || die "couldnt open $gfork_single_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    print "Starting $gfork_prog -c $gfork_single_conf\n";
    $gfork_pid = open($server_fd, "$gfork_prog -c $gfork_single_conf |");
    if($gfork_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    push(@cleanup_files, $server_fd);
    select((select($server_fd), $| = 1)[0]);
    $server_port = <$server_fd>;
    $server_port =~ s/Listening on: //;
    chomp($server_port);
    print "Started gfork on port $server_port\n";

    sleep 1;
    push(@cleanup_pids, $gfork_pid);

    $ENV{FTP_TEST_SOURCE_HOST} = "$server_port";
    $ENV{FTP_TEST_DEST_HOST} = "$server_port";   

    return $gfork_pid,$server_port;
}


sub gfs_setup_server_split()
{
    my $gfork_be_port;
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt;
    my $master_gmap;
    my $x;
    my $sec_envs;
    my $server_be_port;
    my $use_gsi_opt;
    my $gfork_pid;
    my $be_count = shift;
    my $server_fd;

    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $server_nosec = "-aa";
    }

    my $gfork_conf =  $gfs_working_dir . "/gfork_conf";
    $master_gmap = $ENV{GRIDMAP};

    $sec_envs = "GRIDMAP=$ENV{GRIDMAP}";
    if(!defined($ENV{FTP_TEST_NO_GSI}  || $ENV{FTP_TEST_NO_GSI} != 1))
    {
        $sec_envs = "$sec_envs\n  env += X509_CERT_DIR=$ENV{X509_CERT_DIR}";
        $sec_envs = "$sec_envs\n  env += X509_USER_PROXY=$ENV{X509_USER_PROXY}";
        $sec_envs = "$sec_envs\n  env += X509_USER_CERT=$ENV{X509_USER_PROXY}";

        $subject = $gfs_subject;

        $use_gsi_opt = "y";
    }
    else
    {
        $use_gsi_opt = "n";
    }

    # XXX will this due?
    my $reg_port = 8000 + int(rand(1000));

    # sub in the name for frontend
    open(IN, "<$gfork_conf.in") || die "couldnt open $gfork_conf.in";
    open(OUT, ">$gfork_conf") || die "couldnt open $gfork_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@REG_PORT@/$reg_port/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    print "starting $gfork_prog -c $gfork_conf\n";
    $gfork_pid = open($server_fd, "$gfork_prog -c $gfork_conf |");
    if($gfork_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    push(@cleanup_files, $server_fd);
    select((select($server_fd), $| = 1)[0]);
    $server_port = <$server_fd>;
    my $fe_cs = $server_port;
    $fe_cs =~ s/Listening on: //;
    $server_port = $fe_cs;
    chomp($server_port);
    print "Started gfork on port $server_port\n";
    push(@cleanup_pids, $gfork_pid);

    # make sure it all gets loaded before starting the backends
    sleep 5;

    my $gfork_be_pid;
    my $server_be_port;
    my $be_handle;
    
    for(my $i=0; $i < $be_count; $i++)
    {
        ($gfork_be_pid, $server_be_port, $be_handle) = gfs_setup_server_be($reg_port);

        push(@cleanup_files, $be_handle);
    }

    return $gfork_pid,$server_port;
}


sub gfs_setup_server_be()
{
    my $gfork_be_port;
    my $gfork_be_pid;
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt;
    my $master_gmap;
    my $x;
    my $sec_envs;
    my $server_be_port;
    my $use_gsi_opt;
    my $reg_port = shift;
    my $gfork_be_conf = $gfs_working_dir . "/gfork_be_conf";

    my $fe_cs = "localhost:$reg_port";

    $sec_envs = "GRIDMAP=$ENV{GRIDMAP}";
    if(!defined($ENV{FTP_TEST_NO_GSI}  || $ENV{FTP_TEST_NO_GSI} != 1))
    {
        $sec_envs = "$sec_envs\n  env += X509_CERT_DIR=$ENV{X509_CERT_DIR}";
        $sec_envs = "$sec_envs\n  env += X509_USER_PROXY=$ENV{X509_USER_PROXY}";
        $sec_envs = "$sec_envs\n  env += X509_USER_CERT=$ENV{X509_USER_PROXY}";

        $subject = $gfs_subject;

        $use_gsi_opt = "y";
    }
    else
    {
        $use_gsi_opt = "n";
    }


    open(IN, "<$gfork_be_conf.in") || die "couldnt open $gfork_be_conf.in";
    open(OUT, ">$gfork_be_conf") || die "couldnt open $gfork_be_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    $x =~ s/\@FE_CS@/$fe_cs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    my $be_handle;
    print "starting $gfork_prog -c $gfork_be_conf\n";
    $gfork_be_pid = open($be_handle, "$gfork_prog -c $gfork_be_conf |");
    if($gfork_be_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    print "Reading port from be\n";
    select((select($be_handle), $| = 1)[0]);
    $server_be_port = <$be_handle>;
    chomp($server_be_port);
    print "Started gfork backend on port $server_be_port\n";
    push(@cleanup_pids, $gfork_be_pid);

    sleep 5;

    return $gfork_be_pid,$server_be_port,$be_handle;
}

1;
