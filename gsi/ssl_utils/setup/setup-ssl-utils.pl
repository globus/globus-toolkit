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

print "$myname: Configuring ssl-utils package\n";

#
# Run setup-ssl-utils-sh-scripts. This will:
#   -Create grid-security-config from grid-security-config.in
#   -Create grid-cert-request-config from grid-cert-request-config.in
#

print "Running setup-ssl-utils-sh-scripts...\n";

my $result = `$setupdir/setup-ssl-utils-sh-scripts`;

$result = system("chmod 755 $setupdir/grid-security-config");

if ($result != 0) {
  die "Failed to set permissions on $setupdir/grid-security-config";
}

$result = system("chmod 755 $setupdir/grid-cert-request-config");

if ($result != 0) {
  die "Failed to set permissions on $setupdir/grid-cert-request-config";
}

$metadata->finish();

print "$myname: Complete\n";

# End
