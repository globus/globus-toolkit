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

my $metadata = new Grid::GPT::Setup(package_name => "ssl_utils_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";
my $result = `$setupdir/setup-ssl_utils-sh-scripts`;

$result = system("chmod 0755 $setupdir/grid-cert-request-config");

$result = system("chmod 0755 $setupdir/grid-security-config");

$result = system("$setupdir/grid-security-config");

$metadata->finish();
