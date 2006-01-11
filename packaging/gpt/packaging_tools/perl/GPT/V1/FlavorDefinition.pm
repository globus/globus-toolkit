package Grid::GPT::V1::FlavorDefinition;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::FlavorBase;
use Grid::GPT::V1::BuildFlavors;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::V1::FlavorBase);

sub _init {
    my ($me, %arg)  = @_;
    $me->read_xml($arg{'xml'}) if defined $arg{'xml'};
    $me->read_xml_file($arg{'xmlfile'}) if defined $arg{'xmlfile'};
    $me->get_core_config($arg{'build_parameters'}) 
      if (defined($arg{'build_parameters'}));
    $me->{'name'} = $arg{'name'} if defined $arg{'name'};
}
sub _nolabel {
    my ($me, $nolabel)  = @_;
}

sub get_core_config {
  my ($me, $file) = @_;


  open (BUILD, $file) || die "ERROR: Cannot open file $file \n";

  my ($cc_name, $cc_value, $config, $label2);

  for my $l (<BUILD>) {
    chomp $l;
    next if $l !~ m!(\w+)=(.+)$!;
    my ($var, $value) = ($1, $2);

    # remove all quotes this could be trouble some day.
    $value =~ s![\"\']!!g;

    if ($var eq "CC") {
      $cc_value = $l;
      next;
    }
    if ($var eq "ISGCC") {
      $cc_name = "vendorcc";
      $cc_name = "gcc" if $value eq "yes";
      next;
    }
    if ($var eq "CONFIG_PARAMETERS") {
      $config = $value;
      next;
    }
    next if $value !~ m!\w!;
    $me->add_configure_option(nolabel =>$var,switch => $l);
  }

  close BUILD;

  $me->add_configure_option(label =>$cc_name,switch => $cc_value);

  my @configs = split /\s+/, $config;
  $me->{'flavor_list'} = new Grid::GPT::V1::BuildFlavors(core => 1) 
    if ! defined $me->{'flavor_list'};

  for my $s (@configs) {
    for my $choice (@{$me->{'flavor_list'}->{'choices'}}) {
      my @labels = grep {$choice->{$_} eq $s} @{$choice->{'configs'}};
      next if ! @labels;
      $me->add_configure_option(switch =>$s, 
                                $choice->labeled($labels[0]) => $labels[0]);
      last;
    }
  }
  $me->fill_in_defaults();
}

sub fill_in_defaults {
  my ($me) = @_;
  $me->{'flavor_list'} = new Grid::GPT::V1::BuildFlavors(core => 1) 
    if ! defined $me->{'flavor_list'};

  for my $choice (@{$me->{'flavor_list'}->{'choices'}}) {
    my $foundit = 0;;
    for my $c(@{$choice->{'configs'}}) {
      if (grep {$_ eq $c } @{$me->{'configs'}}) {
        $foundit++;
        last;
      } 
    }
    next if $foundit;
    my $nolabel = $choice->{'nolabel'};
    next if $choice->{$nolabel} eq "";
    $me->add_configure_option(switch => $choice->{$nolabel}, 
                                  nolabel=> $nolabel);
  }
}

sub build_core_configure_line {
  my ($me) = @_;
  my $flavor = $me->build_label();
  my ($switches) = ("--with-flavor=$flavor");
  my %env;
  for my $c (@{$me->{configs}}) {
    my $config = $me->{$c};
    next if $config !~ m!\S!;
    if ($config =~ m!\-\-(?:with|enable|disable)!) {
      $switches .= " $config";
    } else {
     my ($var, $value) = $config =~ m!(\w+)=(.+)$!;
     $env{$var} = $value;
    }
  }
    return {env =>\%env, switches => $switches, flavor => $flavor};
}

sub translate_configure_line {
  my ($me, $buildflavors) = @_;
  my $gpt_line = $me->build_core_configure_line();
  my ($env, $switches) = ($gpt_line->{'env'},"");
  my $choices = $buildflavors->{'choices'};
  die "ERROR unidentified flavor choices array\n" 
    if ref $choices ne 'ARRAY' and ref $choices ne "Grid::GPT::V1::FlavorDefinition";

  $choices = $choices->{'choices'} if ref $choices eq "Grid::GPT::V1::FlavorDefinition";

  for my $f (@{$me->{configs}}) {
    my $config;
    for my $c (@$choices) {
      next if ! defined $c->{$f};
      $config = $c->{$f};
      last;
    }
    next if ! defined $config;
    next if $config !~ m!\S!;
    if ($config =~ m!\-\-(?:with|enable|disable)!) {
      $switches .= " $config";
    } elsif ($config =~ m!\w+=\w+!) {
     my ($var, $value) = $config =~ m!(\w+)=(.+)$!;
     $env->{$var} = $value;
    } else {
      $switches .= " $config";
    }
  }
  return {env =>$env, switches => $switches};
}

sub build_label {
  my ($me) = @_;
  my ($label) = ("");
  return $me->{'name'} if defined $me->{'name'};
  for my $c (@{$me->{configs}}) {
    next if ! defined $c;
    $label .= $c if $me->labeled($c) ne 'nolabel';
  }
  $me->{'name'} = $label;
  return $label;
}

sub read_xml_file {
  my ($me, $file) = @_;
  my $xml = new Grid::GPT::V1::XML;
  $xml->read($file);
  my $root = $xml->{'roottag'};
  for my $f (@{$root->{'contents'}}) {
    next if ref($f) ne 'HASH';
    $me->read_xml($f);
  }
}

sub write_xml {
  my ($me, %args) = @_;
  my ($xml, $filename) = ($args{'xml'}, $args{'filename'});
  $xml = Grid::GPT::V1::FlavorBase::open_xml() if defined $filename;

  $me->{'name'} = $me->build_label() 
    if ! defined $me->{'name'};

  $xml->startTag('flavor_definition', label => $me->{'name'});
    $xml->characters("\n");


  $me->write_xml_config(xml=>$xml);

  $xml->endTag('flavor_definition');
    $xml->characters("\n");
  Grid::GPT::V1::FlavorBase::close_xml($xml, $filename) 
      if defined $filename;
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
