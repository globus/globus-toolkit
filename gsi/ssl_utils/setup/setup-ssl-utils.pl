my $gpath = $ENV{GPT_LOCATION};
if (!defined($gpath))
{
  $gpath = $ENV{GLOBUS_LOCATION};

}
if (!defined($gpath))
{
   die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

my $metadata = new Grid::GPT::Setup(package_name => "globus_ssl_utils_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";

my $target_dir = "/etc/grid-security";
my $trusted_certs_dir = $target_dir . "/certificates";

my $myname = "setup-ssl-utils";

if ( -d $target_dir ) {
  print "$myname: GSI configuration directory $target_dir already exists.\n";
  print "$myname: Not doing anything.\n";

} else {

  my $result = `$setupdir/setup-ssl-utils-sh-scripts`;

  $result = system("mkdir $target_dir");

  if ($result != 0) {
    # Make sure we have write permissions
    die "Failed to create $target_dir: $!";
  }

  $result = system("chmod 755 $target_dir");

  $result = system("cp $setupdir/grid-security.conf $target_dir/grid-security.conf");

  $result = system("chmod 0644 $target_dir/grid-security.conf");

  # XXX I believe this can die
  $result = system("chmod 0755 $setupdir/grid-security-config");

  # XXX I believe this can die
  $result = system("chmod 0755 $setupdir/grid-cert-request-config");

  $result = system("$setupdir/grid-security-config");

  # Create trusted certs directory
  $result = system("mkdir $trusted_certs_dir");

  $result = system("chmod 755 $trusted_certs_dir");

  $result = system("cp $setupdir/42864e48.0 $trusted_certs_dir");

  $result = system("chmod 644 $trusted_certs_dir/42864e48.0");

  $result = system("cp $setupdir/42864e48.signing_policy $trusted_certs_dir");

  $result = system("chmod 644 $trusted_certs_dir/42864e48.signing_policy");
}

$metadata->finish();
