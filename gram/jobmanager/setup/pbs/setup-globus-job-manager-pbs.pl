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

my $name		= 'jobmanager-pbs';
my $manager_type	= 'pbs';
my $force		= 0;
my $cmd;
my $host_type = "";

GetOptions('service-name|s=s' => \$name,
           'with-host-type=s' => \$host_type,
	   'force|f' => \$force,
	   'help|h|?' => \$help);

&usage if $help;
&usage if $host_type eq "";

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_pbs");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

if($force != 0)
{
    $force = '-f';
}
else
{
    $force = '';
}

# Do script relocation
print `./find-pbs-tools --with-host-type=$host_type`;
if($? != 0)
{
    print STDERR "Error locating PBS commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service-add -m pbs -s \"$name\" $force";
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
    print "Usage: $0 [options] --with-host-type=cluster|chiba_cluster|smp\n".
          "Options:  [--service-name|-s service_name]\n".
          "          [--force|-f]\n".
	  "          [--help|-h]\n";
    exit 1;
}
