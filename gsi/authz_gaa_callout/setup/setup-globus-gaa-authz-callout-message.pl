require Grid::GPT::Setup;

my $metadata = new Grid::GPT::Setup(package_name => "globus_gaa_authz_callout_setup");

print "
If you wish to configure the optional GAA-based Globus Authorization
callouts, run the setup-globus-gaa-authz-callout setup script.

";

$metadata->finish();
