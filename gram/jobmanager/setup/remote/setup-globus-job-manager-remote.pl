my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script";
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;
use Getopt::Long;

my $name		= 'jobmanager-remote';
my $host;
my $type;
my $location;
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'host|h=s'  => \$host,
	   'type|t=s' => \$type,
	   'location|l=s' => \$location,
	   'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_remote");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

if($host eq "" || $type eq "" || $location eq "")
{
    &usage;
}

# Do script relocation
print `./find-remote-tools --with-host=$host --with-location=$location --with-manager=$type`;
if($? != 0)
{
    print STDERR "Error locating remote commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m remote -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");

if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

sub usage
{
    print "Usage: $0 [options] -host=HOST -type=TYPE -location=LOCATION\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--help|-h]\n";
    exit 1;
}
