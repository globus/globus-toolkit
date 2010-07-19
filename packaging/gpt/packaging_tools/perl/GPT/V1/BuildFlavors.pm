package Grid::GPT::V1::BuildFlavors;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::FlavorDefinition;
use Grid::GPT::V1::FlavorChoices;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::GPTObject);

sub new {
    my ($that, %args)  = @_;
    my $class = ref($that) || $that;
    my $me  = {
               choices => [],
               standard => $args{'std'},
               locations => $args{'locations'},
		};
    bless $me, $class;

    my $gpath = $ENV{GPT_LOCATION};
    
    if (!defined($gpath))
      {
        $gpath = $ENV{GLOBUS_LOCATION};
      }
    my $confdir = "$gpath/etc/gpt";

    if (defined $args{'core'}) {

      my $conf_file = "$confdir/globus_flavor_labels.conf";
      $conf_file = $args{'cfg'} if defined $args{'cfg'};
      my $choicefile = new Grid::GPT::V1::XML;
      $choicefile->read($conf_file);
      my $root = $choicefile->{'roottag'};
      $me->read_xml_choices($root);

      my $flavorlist = $me->permute();
      $me->{'flavors'} = [];
      for my $f (@$flavorlist) {
        $f->{'name'} = $f->build_label() if ! defined $f->{'name'};
        $me->{$f->{'name'}} = $f;
        push @{$me->{'flavors'}}, $f->{'name'};
      }
    }

    if (defined $args{'xml'}) {
      $me->read_xml_choices($args{'xml'});
    }

    if (defined $args{'installed'}) {

      my $gpath = $me->{'locations'}->installdir();


      $me->{'flavors'} = [];

      if (-d "$gpath/etc/globus_core") {
        opendir(CONFDIR, "$gpath/etc/globus_core") 
          || die "ERROR:BuildFlavors: $gpath/etc/globus_core cannot be accessed\n";

        my @flavorfiles = grep {m!flavor_\w+.gpt!} readdir(CONFDIR);

        closedir(CONFDIR);
        for my $ff (@flavorfiles) {
          my $obj = 
            new Grid::GPT::V1::FlavorDefinition(xmlfile => 
                                            "$gpath/etc/globus_core/$ff");
          $me->{$obj->{'name'}} = $obj;
          push @{$me->{'flavors'}}, $obj->{'name'};
        }
      }
    }
##print Dumper $me;
    return $me;
}

sub read_xml_choices {
  my ($me, $xml) = @_;
  for my $f (@{$xml->{'contents'}}) {
    next if ref($f) ne 'HASH';
    my $choice = new Grid::GPT::V1::FlavorChoices(xml => $f);
    push @{$me->{'choices'}}, $choice;
  }
}

sub write_xml_choices {
  my ($me, $xml) = @_;
  $xml->startTag('flavors');
  $xml->characters("\n");
  for my $f (@{$me->{'choices'}}) {
    $f->write_xml(xml => $xml);
  }
  $xml->endTag('flavors');
  $xml->characters("\n");
}

sub permute {
  my ($me, %arg) = @_;
  my @flavors;
  
  my $masterc = defined $arg{'choice'} ? $arg{'choice'} : 0;
  my $choice = $me->{'choices'}->[$masterc];
  my $oldlist = $arg{'list'};
  my $newlist = [];
  
  if (! defined($oldlist)) {
    $newlist = $choice->permute(std => $me->{'standard'});
  } else {
    for my $f (@$oldlist) {
      my $locallist = $choice->permute(flavor => $f, std => $me->{'standard'});
      push @$newlist, @$locallist;
    }
  }
  return $me->permute(choice => $masterc + 1, list => $newlist) 
    if $masterc < @{$me->{'choices'}} - 1;
  return $newlist;
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

sub build_macros {
  my ($me, $macros,$noswitches)=  @_;
  for my $f (@{$me->{'flavors'}}) {
   my $fo = $me->{$f}->build_core_configure_line();
   $macros->{"$fo->{'flavor'}_CONFIGOPTS_GPTMACRO"} = $fo->{'switches'} 
     if ! $noswitches;
   $macros->{"$fo->{'flavor'}_ENV_GPTMACRO"} = $fo->{'env'};
  }
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
