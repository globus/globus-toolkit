package Grid::GPT::V1::FlavorBase;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

{
  my $globals = {format_version => "0.1"};
  sub xml_format_version { return $globals->{'format_version'}};
}

sub new {
    my ($that, %arg)  = @_;
    my $class = ref($that) || $that;
    my $me  = {
               configs => [],
              };
    bless $me, $class;

    $me->_init(%arg);

    return $me;
}

sub add_configure_option {
  my ($me, %arg) = @_;

  return if ! keys %arg;

  my $label2 = 'label';

  if (defined $arg{'nolabel'}){
    $me->_nolabel($arg{'nolabel'});
    $me->{"nolabel_$arg{'nolabel'}"} = $arg{'nolabel'};
    $label2 = 'nolabel';
  }

  if (! defined $arg{$label2}) {
    print "ERROR: Unlabeled config ";
    for (sort keys %arg) {
      print "$_ => $arg{$_} ";
    }
    die "\n";
  }

  my $switch_value = defined $arg{'switch'} ? $arg{'switch'} : '';
  $me->{$arg{$label2}} = $switch_value;
  push @{$me->{'configs'}}, $arg{$label2};
  $me->{"std_$arg{$label2}"} = 1 if defined $arg{'std'} 
    and $arg{'std'} eq 'yes';
  $me->{"invalid_$arg{$label2}"} = 1 if defined $arg{'invalid'};

}

sub is_std {
  my ($me, $c) = @_;
  return defined $me->{"std_$c"};
}

sub is_valid {
  my ($me, $c) = @_;
  return ! defined $me->{"invalid_$c"};
}

sub labeled {
  my ($me, $c) = @_;
  return 'label' if ! defined $c;
  return 'nolabel' if defined $me->{"nolabel_$c"};
  return 'label';
}

sub read_xml {
  my ($me, $xml) = @_;
  $me->{'name'} = $xml->{'attributes'}->{'label'};
  for my $c (@{$xml->{'contents'}}) {
    next if ref($c) ne 'HASH';
    $me->add_configure_option(%{$c->{'attributes'}});
  }
}

sub write_xml_config {
  my ($me, %args) = @_;
  my ($xml) = ($args{'xml'});

  for my $c (@{$me->{'configs'}}) {
    my %atts;
    my $label2 = 'label';
    if (defined $me->{"nolabel_$c"}){
      $label2 = 'nolabel';
    }

    $atts{$label2} = $c;
    $atts{'switch'} = $me->{$c} if $me->{$c} ne '';
    $atts{'std'} = "yes" if defined $me->{"std_$c"};
    $atts{'invalid'} = "yes" if defined $me->{"invalid_$c"};

    $xml->emptyTag("config",%atts);
    $xml->characters("\n");
  }
}

sub dump {
  my ($me, %args) = @_;
  my $result;

  for my $c (@{$me->{'configs'}}) {
    my %atts;
    my $label2 = 'label';
    if (defined $me->{"nolabel_$c"}){
      $label2 = 'nolabel';
    }

    $result .= " /$label2=$c";
    $result .= "/switch='$me->{$c}'"if $me->{$c} ne '';
    $result .= "/std=yes" if defined $me->{"std_$c"};
    $result .= "/invalid=yes" if defined $me->{"invalid_$c"};
    $result .= "\n";
  }
  return $result;
}

sub clone {
    my $me = shift;
    my $class = ref $me;
    my $clone = new $class;
    replicate($me, $clone);
    return $clone;
}

# Some utility functions

sub replicate {
  my ($rold, $newclass) = @_;
  if (ref(\$rold) eq 'SCALAR') {
    return $rold;
  } elsif (ref($rold) eq 'ARRAY') {
    my @list = @$rold;
    return \@list;
  } elsif (ref($rold) eq 'HASH') {
    my $rnew = {};
    for my $e (sort keys %$rold) {
      $rnew->{$e} = replicate($rold->{$e});
    }
    return $rnew;

  } elsif (ref($rold) =~ m!Grid::GPT! ) {
    for my $e (sort keys %$rold) {
      $newclass->{$e} = replicate($rold->{$e});
    }
    return;
  }
}

sub open_xml {
  my $writer = new Grid::GPT::V1::XML;  
  $writer->doctype("gpt_package_metadata","package.dtd");
  $writer->startTag("flavors",
		    Format_Version =>xml_format_version());
  $writer->characters("\n");
  return $writer;
}

sub close_xml {
  my ($writer, $filename) = @_;
  $writer->endTag('flavors');
  $writer->write($filename);
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
