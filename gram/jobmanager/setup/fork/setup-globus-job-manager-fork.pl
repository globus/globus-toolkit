use Grid::GPT::Setup;
use Getopt::Long;

my $name		= 'jobmanager-fork';
my $manager_type	= 'fork';
my $force		= 0;
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'force|f' => \$force,
	   'help|h|?' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_job_manager_setup_fork");

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

print `./find-fork-tools`;

$cmd = "$libexecdir/globus-job-manager-service-add -m fork -s \"$name\" $force";
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
          "          [--force|-f]\n".
	  "          [--help|-h]\n";
    exit 1;
}
