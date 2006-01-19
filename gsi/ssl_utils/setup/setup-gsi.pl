

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

#
# Set up GSI configuration in /etc/grid-security
#
# This script is intended to be run as root.
#

use Getopt::Long;
use English;

my $globusdir = $ENV{GLOBUS_LOCATION};

if (!defined($globusdir)) {
  die "GLOBUS_LOCATION needs to be set before running this script";
}

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
  $gpath = $globusdir;

}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

if( ! &GetOptions("nonroot|d:s","help!") ) 
{
   pod2usage(1);
}

if(defined($opt_help))
{
   pod2usage(0);
}

my $setupdir = "$globusdir/setup/globus/";
my $trusted_certs_dir = undef;

my $target_dir = "";

if(defined($opt_nonroot))
{
    if($opt_nonroot eq "") 
    {
	$target_dir = $globusdir . "/etc/";
    } 
    else 
    {
	$target_dir = "$opt_nonroot";
    }

    $trusted_certs_dir = $globusdir . "/share/certificates/";    
}
else
{
   $target_dir = "/etc/grid-security/";
   $trusted_certs_dir = $target_dir . "/certificates/";
}
    
$ENV{GRID_SECURITY_DIR} = "$target_dir";
$ENV{TRUSTED_CA_DIR}    = "$trusted_certs_dir";

my $myname = "setup-gsi";

print "$myname: Configuring GSI security\n";

#
# Create /etc/grid-security if not already there.
# If it is there, make sure we have write permissions
#
if ( -d $target_dir ) 
{
  if ( ! -w $target_dir ) 
  {
    die "Don't have write permissions on $target_dir. Aborting.";
  }

} 
else 
{

  print "Making $target_dir...\n";

  $result = system("mkdir $target_dir");
  $result += system("mkdir $trusted_certs_dir");

  if ($result != 0) 
  {
    die "Failed to create $target_dir. Aborting.";
  }

  $result = system("chmod 755 $target_dir");

  if ($result != 0) 
  {
    die "Failed to set permissions on $target_dir. Aborting.";
  }

  $result = system("chmod 755 $trusted_certs_dir");

  if ($result != 0) 
  {
    die "Failed to set permissions on $trusted_certs_dir. Aborting.";
  }

}

#
# Create /etc/grid-security.conf if not present
#
print "Installing $target_dir/grid-security.conf...\n";

$result = system("cp $setupdir/grid-security.conf $target_dir/grid-security.conf");

if ($result != 0) 
{
  die "Failed to install grid-security.conf. Aborting.";
}

$result = system("chmod 0644 $target_dir/grid-security.conf");

if ($result != 0) 
{
  die "Failed to set permissions on grid-security.conf. Aborting.";
}

#
# Run grid-security-config to generate globus-host-ssl.conf
# and globus-user-ssl.conf in $target_dir
# Note that this script is interactive.
#
print "Running grid-security-config...\n";

$result = system("$setupdir/grid-security-config");

if ($result != 0) 
{
  die "Error running grid-security-config. Aborting.";
}

#
# Create trusted certificate directory if not present
#
if ( ! -d $trusted_certs_dir ) 
{
  print "Making trusted certs directory: $trusted_certs_dir\n";

  $result = system("mkdir $trusted_certs_dir");

  if ($result != 0) 
  {
    die "Failed to create $trusted_certs_dir. Aborting.";
  }

  $result = system("chmod 755 $trusted_certs_dir");

  if ($result != 0) 
  {
    die "Failed to set permissions on $trusted_certs_dir. Aborting.";
  }
}


#
# Install Globus CA certificate if not present
#
print "Installing Globus CA certificate into trusted CA certificate directory...\n";

$result = system("cp $setupdir/42864e48.0 $trusted_certs_dir");

if ($result != 0) 
{
  die "Failed to install $trusted_certs_dir/42864e48.0. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/42864e48.0");

if ($result != 0) 
{
  die "Failed to set permissions on $trusted_certs_dir/42864e48.0. Aborting.";
}

#
# Install Globus CA policy file if not present
#
print "Installing Globus CA signing policy into trusted CA certificate directory...\n";

$result = system("cp $setupdir/42864e48.signing_policy $trusted_certs_dir");

if ($result != 0) 
{
  die "Failed to install $trusted_certs_dir/42864e48.signing_policy. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/42864e48.signing_policy");

if ($result != 0) 
{
  die "Failed to set permissions on $trusted_certs_dir/42864e48.signing_policy. Aborting.";
}

print "$myname: Complete\n";

my @statres = stat "$globusdir/etc/globus_packages/globus_ssl_utils_setup/pkg_data_noflavor_rtl.gpt";

if($statres[4] != $EUID)
{
   $EGID = $statres[5];
   $EUID = $statres[4];
}

my $metadata = new Grid::GPT::Setup(package_name => "globus_ssl_utils_setup");

$metadata->finish();

sub pod2usage 
{
  my $ex = shift;

  print "setup-gsi [
              -help
              -nonroot[=path] 
                 sets the directory that the security configuration
	         files will be placed in.  If no argument is given,
	         the config files will be placed in \$GLOBUS_LOCATION/etc/
                 and the CA files will be placed in  
                 \$GLOBUS_LOCATION/share/certificates.
          ]\n";

  exit $ex;
}

# End
