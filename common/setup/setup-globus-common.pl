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

my $metadata = new Grid::GPT::Setup(package_name => "globus_common_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";

print "Creating globus-hostname\n";
print "Creating globus-domainname\n";
my $result = `$setupdir/setup-common-sh-scripts`;
$result = system("chmod 0755 $setupdir/globus-hostname");

if (!(-d "$globusdir/bin")){
	$result = system("mkdir $globusdir/bin");
}
	
$result = system("cp globus-hostname $globusdir/bin");
$result = system("cp globus-hostname $globusdir/bin/globus-domainname");

$result = system("chmod 0755 $globusdir/bin/globus-hostname");
$result = system("chmod 0755 $globusdir/bin/globus-domainname");

my $hostname = `$setupdir/globus-hostname`;

$hostname =~ s/\w//g; #strip whitespace

if( ("$hostname" eq "localhost.") || 
	("$hostname" eq "localhost.localdomain") ||
	("$hostname" eq "."))
{
   print "WARNING: globus-hostname was unable to determine a valid hostname\n";
   print "WARNING: this may lead to problems with other programs that\n";
   print "WARNING: depend on globus-hostname. To avoid this please set the\n";
   print "WARNING: GLOBUS_HOSTNAME environment variable\n";
}

print "Done\n";

$metadata->finish();
