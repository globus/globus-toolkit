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

use Grid::GPT::Setup;
use Getopt::Long;
use English;
use File::Path;

if(!&GetOptions("help|h","force|f","server|s","nonroot|n")) 
{
    usage(1);
}

if(defined($opt_help))
{
    usage(0);
}

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gridftp_sshftp_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $sshprog = `which ssh`;
chomp $sshprog;
######################################################
my $sshftp = <<EOF;
#!/bin/sh

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

export GLOBUS_LOCATION=$globusdir
. \$GLOBUS_LOCATION/etc/globus-user-env.sh

#export GLOBUS_TCP_PORT_RANGE=50000,50100

\$GLOBUS_LOCATION/sbin/globus-gridftp-server -ssh 
# -data-interface <interface to force data connections>
EOF

######################################################

my $gridftpssh = <<EOF;
#!/bin/sh

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

url_string=\$1
remote_host=\$2
port=\$3
user=\$4

port_str=""
if  [ "X" = "X\$port" ]; then
    port_str=""
else
    port_str=" -p \$port "
fi

if  [ "X" != "X\$user" ]; then
    remote_host="\$user@\$remote_host"
fi

remote_default1=.globus/sshftp
remote_default2=/etc/grid-security/sshftp

remote_program=\$GLOBUS_REMOTE_SSHFTP
if  [ "X" = "X\$remote_program" ]; then
    remote_program="(( test -f \$remote_default1 && \$remote_default1 ) || \$remote_default2 )"
fi

$sshprog \$port_str \$remote_host \$remote_program
EOF

######################################################

umask(022);

if(defined($opt_server))
{
    if(defined($opt_nonroot))
    {
        mkdir "$ENV{HOME}/.globus" unless (-d "$ENV{HOME}/.globus");
        $target = "$ENV{HOME}/.globus/sshftp";
    }
    else
    {
        mkdir "/etc/grid-security" unless (-d "/etc/grid-security");
        $target = "/etc/grid-security/sshftp"; 
    }

    open(FILE, "> $target") ||
        die("Error while trying to open $target. Check your permissions\n");
    print FILE $sshftp;
    close(FILE);
    chmod 0755, $target;
    print "Successfully created $target\n";
}
else
{
    if(defined($opt_nonroot))
    {
        mkdir "$ENV{HOME}/.globus" unless (-d "$ENV{HOME}/.globus");
        $target = "$ENV{HOME}/.globus/gridftp-ssh";
    }
    else
    {
        $target = "$globusdir/libexec/gridftp-ssh";
    }

    print <<EOF;
    
##############################################################
##############################################################

Creating client support scripts for GridFTP over ssh.  This will allow 
GridFTP clients from this installation to access sshftp:// urls.  


You will still need to run the following command as 'root' to enable 
this machine to *accept* sshftp connections.  This will create the 
file /etc/grid-security/sshftp.

    \$GLOBUS_LOCATION/setup/globus/setup-globus-gridftp-sshftp -server

    
If root access is not available, the option -nonroot may be added
to enable connections as your user only.  This will create the file
\$HOME/.globus/sshftp.

    \$GLOBUS_LOCATION/setup/globus/setup-globus-gridftp-sshftp -server -nonroot

##############################################################
##############################################################    

EOF
    open(FILE, "> $target") ||
        die("Error while trying to open $target. Check your permissions\n");
    print FILE $gridftpssh;
    close(FILE);
    chmod 0755, $target;
    print "Successfully created $target\n\n";
}


 
if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error setting up SSHFTP.\n";
}

sub usage
{
    my $ex = shift;
    print "Usage: setup-globus-gridftp-sshftp [options]\n".
          "Options:  [-server] [-force] [-help|-h]\n";
    exit $ex;
}

