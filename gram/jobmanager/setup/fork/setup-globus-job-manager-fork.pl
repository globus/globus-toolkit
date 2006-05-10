use Grid::GPT::Setup;
use Getopt::Long;

my $name                = 'jobmanager-fork';
my $softenv_dir         = '';
my $manager_type        = 'fork';
my $cmd;

GetOptions('service-name|s=s' => \$name,
           'softenv-dir|e=s' => \$softenv_dir,
           'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_fork");

my $globusdir       = $ENV{GLOBUS_LOCATION};
my $libexecdir      = "$globusdir/libexec";
my $setupdir        = "$globusdir/setup/globus";

chdir $setupdir;

mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager", 0777;

print `./find-fork-tools --with-softenv-dir=$softenv_dir`;

$cmd = "$libexecdir/globus-job-manager-service -add -m fork -s \"$name\"";
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
          "          [--softenv-dir|-e softenv_install_dir ]\n";
          "          [--help|-h]\n";
    exit 1;
}
