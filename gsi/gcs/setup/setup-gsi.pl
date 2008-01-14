
#
# Set up GSI configuration in /etc/grid-security
#
# This script is intended to be run as root.
#

use Getopt::Long;
use English;
use File::Path;

my $globusdir = $ENV{GLOBUS_LOCATION};

if (!defined($globusdir)) 
{
  die "GLOBUS_LOCATION needs to be set before running this script";
}

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
  $gpath = $globusdir;

}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

if( ! &GetOptions("nonroot|d:s","help!","default!") ) 
{
   pod2usage(1);
}

if(defined($opt_help))
{
   pod2usage(0);
}

my $setupdir = "$globusdir/setup/globus_gcs_b38b4d8c_setup/";

my $target_dir = "";
my $trusted_certs_dir = "";

my $ca_install_hash = "b38b4d8c";

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
   $target_dir = "/etc/grid-security";
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

  $result = mkpath("$target_dir",1,0755);

  if ($result == 0) 
  {
    die "Failed to create $target_dir. Aborting.";
  }

}

#
# Create trusted certificate directory if not present
#
if ( -d $trusted_certs_dir ) 
{
    if ( ! -w $trusted_certs_dir ) 
    {
        die "Don't have write permissions on $trusted_certs_dir. Aborting.";
    }
} 
else 
{
    print "Making trusted certs directory: $trusted_certs_dir\n";
    
    $result = mkpath("$trusted_certs_dir",1,0755);
    
    if ($result == 0) 
    {
        die "Failed to create $trusted_certs_dir. Aborting.";
    }
}

#
# Create /etc/grid-security.conf if not present
#
print "Installing $trusted_certs_dir/grid-security.conf.$ca_install_hash...\n";

$result = system("cp $setupdir/grid-security.conf.$ca_install_hash $trusted_certs_dir/grid-security.conf.$ca_install_hash");

if ($result != 0) 
{
  die "Failed to install grid-security.conf.$ca_install_hash Aborting.";
}

$result = system("chmod 0644 $trusted_certs_dir/grid-security.conf.$ca_install_hash");

if ($result != 0) 
{
  die "Failed to set permissions on grid-security.conf.$ca_install_hash Aborting.";
}

#
# Run grid-security-config to generate globus-host-ssl.conf
# and globus-user-ssl.conf in $trusted_certs_dir
# Note that this script is interactive.
#
print "Running grid-security-config...\n";

$result = system("$setupdir/grid-security-config");

if ($result != 0) 
{
  die "Error running grid-security-config. Aborting.";
}


#
# Install Globus CA certificate if not present
#
print "Installing GCS CA certificate into trusted CA certificate directory...\n";

$result = system("cp $setupdir/${ca_install_hash}.0 $trusted_certs_dir");

if ($result != 0) 
{
  die "Failed to install $trusted_certs_dir/${ca_install_hash}.0. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/${ca_install_hash}.0");

if ($result != 0) 
{
  die "Failed to set permissions on $trusted_certs_dir/${ca_install_hash}.0. Aborting.";
}

#
# Install Globus CA policy file if not present
#
print "Installing GCS CA signing policy into trusted CA certificate directory...\n";

$result = system("cp $setupdir/${ca_install_hash}.signing_policy $trusted_certs_dir");

if ($result != 0) 
{
  die "Failed to install $trusted_certs_dir/${ca_install_hash}.signing_policy. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/${ca_install_hash}.signing_policy");

if ($result != 0) 
{
  die "Failed to set permissions on $trusted_certs_dir/${ca_install_hash}.signing_policy. Aborting.";
}

#
# Install Globus CA directions file if not present
#
print "Installing GCS CA directions into trusted CA certificate directory...\n";

$result = system("cp $setupdir/directions $trusted_certs_dir/directions.${ca_install_hash}");

if ($result != 0) 
{
  die "Failed to install $trusted_certs_dir/directions.${ca_install_hash}. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/directions.${ca_install_hash}");

if ($result != 0) 
{
  die "Failed to set permissions on $trusted_certs_dir/directions.${ca_install_hash}. Aborting.";
}

if(defined($opt_default))
{

	system "rm -f $target_dir/grid-security.conf";
	my $ret_value = ($? >> 8);
	system "rm -f $target_dir/globus-user-ssl.conf";
	$ret_value += ($? >> 8);
	system "rm -f $target_dir/globus-host-ssl.conf";
	$ret_value += ($? >> 8);
	system "rm -f $target_dir/directions";

	if($ret_value > 0) { die "\nERROR: Can't delete security config files from $target_dir\n\n"; }

	my $ret_value  = symlink("${trusted_certs_dir}/grid-security.conf.${ca_install_hash}",   "${target_dir}/grid-security.conf");
	$ret_value += symlink("${trusted_certs_dir}/globus-user-ssl.conf.${ca_install_hash}", "${target_dir}/globus-user-ssl.conf");
	$ret_value += symlink("${trusted_certs_dir}/globus-host-ssl.conf.${ca_install_hash}", "${target_dir}/globus-host-ssl.conf");
	$ret_value += symlink("${trusted_certs_dir}/directions.${ca_install_hash}", "${target_dir}/directions");
	if($ret_value < 4) { die "\nERROR: Can't create symlinks for security config files from $trusted_certs_dir to $target_dir\n\n"; }

}

my @statres = stat "$globusdir/etc/globus_packages/globus_trusted_ca_${ca_install_hash}_setup/pkg_data_noflavor_data.gpt";

if($statres[4] != $EUID)
{
   ($EUID,$EGID) = ($statres[4],$statres[5]);
}
    
my $metadata = new Grid::GPT::Setup(package_name => "globus_gcs_${ca_install_hash}_setup");

$metadata->finish();


print "$myname: Complete\n";


sub pod2usage 
{
  my $ex = shift;

  print "setup-gsi [

              -help

              -nonroot[=path] 
                 sets the directory that the security 
                 configuration files will be placed in.  
                 If no argument is given, the config files 
                 will be placed in \$GLOBUS_LOCATION/etc/
                 and the CA files will be placed in  
                 \$GLOBUS_LOCATION/share/certificates.
              
              -default
                 sets the CA being installed to be the
                 default CA for this host.
          ]\n";

  exit $ex;
}


# End
