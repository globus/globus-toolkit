use Grid::GPT::Setup;
use Getopt::Long;
use File::Copy;

GetOptions('help|h' => \$help);

&usage if $help;

my $metadata = new Grid::GPT::Setup(package_name => "globus_rft_setup");

chdir( $ENV{'GLOBUS_LOCATION'} );
print `ant -f $ENV{'GLOBUS_LOCATION'}/build.xml deploy -Dgar.name=$ENV{'GLOBUS_LOCATION'}/gars/multirft.gar`;

if ($? == 0) {
    $metadata->finish();
    exit 0;
}

print STDERR "Error configuring rft\n";
exit 1;

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--help|-h]\n";
    exit 1;
}
