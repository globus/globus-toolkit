
#
# Set up GSI configuration in /etc/grid-security
#
# This script is intended to be run as root.
#

my $globusdir = $ENV{GLOBUS_LOCATION};

if (!defined($globusdir)) {
  die "GLOBUS_LOCATION needs to be set before running this script";
}

my $setupdir = "$globusdir/setup/globus/";

my $target_dir = "/etc/grid-security";
my $trusted_certs_dir = $target_dir . "/certificates";

my $myname = "setup-gsi";

print "$myname: Configuring GSI security\n";

#
# Create /etc/grid-security if not already there.
# If it is there, make sure we have write permissions
#
if ( -d $target_dir ) {

  if ( ! -w $target_dir ) {
    die "Don't have write permissions on $target_dir. Aborting.";
  }

} else {

  print "Making $target_dir...\n";

  $result = system("mkdir $target_dir");

  if ($result != 0) {
    die "Failed to create $target_dir. Aborting.";
  }

  $result = system("chmod 755 $target_dir");

  if ($result != 0) {
    die "Failed to set permissions on $target_dir. Aborting.";
  }
}

#
# Create /etc/grid-security.conf if not present
#
print "Installing $target_dir/grid-security.conf...\n";

$result = system("cp $setupdir/grid-security.conf $target_dir/grid-security.conf");

if ($result != 0) {
  die "Failed to install grid-security.conf. Aborting.";
}

$result = system("chmod 0644 $target_dir/grid-security.conf");

if ($result != 0) {
  die "Failed to set permissions on grid-security.conf. Aborting.";
}

#
# Run grid-security-config to generate globus-host-ssl.conf
# and globus-user-ssl.conf in $target_dir
# Note that this script is interactive.
#
print "Running grid-security-config...\n";

$result = system("$setupdir/grid-security-config");

if ($result != 0) {
  die "Error running grid-security-config. Aborting.";
}

#
# Create trusted certificate directory if not present
#
if ( ! -d $trusted_certs_dir ) {
  print "Making trusted certs directory: $trusted_certs_dir\n";

  $result = system("mkdir $trusted_certs_dir");

  if ($result != 0) {
    die "Failed to create $trusted_certs_dir. Aborting.";
  }

  $result = system("chmod 755 $trusted_certs_dir");

  if ($result != 0) {
    die "Failed to set permissions on $trusted_certs_dir. Aborting.";
  }
}


#
# Install Globus CA certificate if not present
#
print "Installing Globus CA certificate into trusted CA certificate directory...\n";

$result = system("cp $setupdir/42864e48.0 $trusted_certs_dir");

if ($result != 0) {
  die "Failed to install $trusted_certs_dir/42864e48.0. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/42864e48.0");

if ($result != 0) {
  die "Failed to set permissions on $trusted_certs_dir/42864e48.0. Aborting.";
}

#
# Install Globus CA policy file if not present
#
print "Installing Globus CA signing policy into trusted CA certificate directory...\n";

$result = system("cp $setupdir/42864e48.signing_policy $trusted_certs_dir");

if ($result != 0) {
  die "Failed to install $trusted_certs_dir/42864e48.signing_policy. Aborting.";
}

$result = system("chmod 644 $trusted_certs_dir/42864e48.signing_policy");

if ($result != 0) {
  die "Failed to set permissions on $trusted_certs_dir/42864e48.signing_policy. Aborting.";
}

print "$myname: Complete\n";

# End
