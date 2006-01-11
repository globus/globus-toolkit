package Grid::GPT::V1::FlavorChoices;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::FlavorDefinition;
use Grid::GPT::V1::FlavorBase;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::V1::FlavorBase);

sub _init {
    my ($me, %arg)  = @_;
    $me->read_xml($arg{'xml'}) if (defined($arg{'xml'}));
}

sub _nolabel {
    my ($me, $nolabel)  = @_;
    die "ERROR: multiple nolabel\'s defined: $nolabel $me->{'nolabel'}\n"
      if defined $me->{"nolabel"};

    $me->{'nolabel'} = $nolabel;
}

sub write_xml {
  my ($me, %args) = @_;

  $me->write_xml_config(%args);
}

sub permute {
  my ($me, %arg) = @_;
  my ($flavor, $std) = ($arg{'flavor'}, $arg{'std'});
  my @list;
  my $myflavor = $flavor;
  $myflavor = new Grid::GPT::V1::FlavorDefinition if ! defined $flavor;
  for my $c (@{$me->{'configs'}}) {
    my $mystd = $me->is_std($c);
    next if defined $std and ! $mystd;
    my $newflavor = $myflavor->clone();
    $newflavor->add_configure_option($me->labeled($c) => $c, 
                                     switch => $me->{$c}
                                    );
    push @list, $newflavor;
  }
  return \@list;
}

sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $me = shift;
  my $type = ref($me) || croak "$me is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $me->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
  } 
  if (@_) {
    return $me->{$name} = shift;
  } else {
    return $me->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)



1;
__END__
