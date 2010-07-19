package Grid::GPT::PackageFactory;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Package;

# set the version for version checking
$VERSION     = 0.01;
my $_DEBUG   = 0;

my %table;

sub new { 
  my $that   = shift;
  my $class  = ref($that) || $that;
  my $self   = {};

  bless $self, $class;
  return $self;
}

sub type_of_package {
  my $self   = shift;
  my ($filename,$pkg_type) = @_;

  $filename  = "$ {filename}_$pkg_type.gpt" if(defined($pkg_type));
  my $xml    = new Grid::GPT::V1::XML;

  $xml->read($filename);

  my $root   = $xml->{'roottag'};

# Check to see if we can understand this format

  if( $root->{'name'}    eq 'GPTPackageMetadata' )
  {
    return( undef );
  }
  elsif( $root->{'name'} eq 'gpt_package_metadata' )
  {
    return( new Grid::GPT::V1::Package );
  }
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
