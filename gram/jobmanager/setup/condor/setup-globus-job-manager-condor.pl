use Grid::GPT::Setup;
use Getopt::Long;

my $name		= 'jobmanager-condor';
my $manager_type	= 'condor';
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_condor");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager";

print `./find-condor-tools`;

$cmd = "$libexecdir/globus-job-manager-service-add -m condor -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");

if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating service entry $name.\n";
}

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--help|-h]\n";
    exit 1;
}
