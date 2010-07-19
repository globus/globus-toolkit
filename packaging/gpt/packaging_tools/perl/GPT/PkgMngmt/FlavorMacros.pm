package Grid::GPT::PkgMngmt::FlavorMacros;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Cwd;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';

# Preloaded methods go here.

sub new {
  my ($class, %args) = @_;
  my $me = {
            flavors => $args{'flavors'},
            macrolist => {
                          CORE_CONFIG_GPTMACRO =>1,
                          CORE_ENV_GPTMACRO =>1,
                         },
            user_macros => $args{'user_macros'},
            log => $args{'log'},
            already_done => {},
	   };

  bless $me, $class;

#  for my $f (@{$me->{'flavors'}->{'flavors'}}) {
#    print "Dumping $f:", $me->{'flavors'}->{$f}->dump(), "\n";
#  }

  return $me;
}

sub macros {
  my ($me, %args) = @_;
  my ($flavor, $core, $user_macros) = ($args{'flavor'}, 
                                       $args{'core'},
                                       $me->{'user_macros'},
                                      );

  if (defined $core and 
    defined $user_macros->{"$ {flavor}_CONFIG_GPTMACRO"} and 
      defined $user_macros->{"$ {flavor}_ENV_GPTMACRO"}) {

    # Move definitions over to 'CORE'
    return { "$ {flavor}_CORE_CONFIG_GPTMACRO" => 
             $user_macros->{"$ {flavor}_CONFIG_GPTMACRO"},
             "$ {flavor}_CORE_ENV_GPTMACRO" =>
             $user_macros->{"$ {flavor}_ENV_GPTMACRO"}};
  }
  return $me->macros_from_flavor(flavor=>$flavor);
}

sub macros_from_flavor {
  my ($me, %args) = @_;
  my ($flavor) = ($args{'flavor'});
  my (%macros, $core_switches, $core_envs);

  return undef if $flavor eq 'noflavor';

  return undef if $me->{'already_done'}->{$flavor};

  for my $c (@{$me->{'flavors'}->{$flavor}->{'configs'}}) {

    my $label2 = 'label';
    if (defined $me->{'flavors'}->{$flavor}->{"nolabel_$c"}){
      $label2 = 'nolabel';
    }
    
    my $switch = $me->{'flavors'}->{$flavor}->{$c};
    if ($switch =~ m!--(:?with|enable|disable)!) {
      $core_switches .= "$switch ";
      next;
    }

    my ($var, $value) = $switch =~ m!([^=]+)=(.+)!;
    next if ! defined $var;

    $var =~ s!^\s*(\S+)\s+$!$1!;

    #Dirty hack to compensate for double CXX entry.
    if ($value =~ m!([^;]+);?\s+CXX\s*=(.+)!) {
      my ($cvalue, $cxxvalue) = ($1, $2);
      $value = $cvalue;
#      print "VAR: CXX = $cxxvalue\n";
      $macros{"$ {flavor}_CXX_GPTMACRO"} = "CXX=$cxxvalue; export CXX;";
      $macros{"$ {flavor}_CXX_VALUE_GPTMACRO"} = "$cxxvalue";
      $me->{'macrolist'}->{'CXX_GPTMACRO'}++;
    }

#    print "VAR: $var = $value\n";
    $macros{"$ {flavor}_$ {var}_GPTMACRO"} = "$var=$value; export $var;";
    $macros{"$ {flavor}_$ {var}_VALUE_GPTMACRO"} = "$value";
    $core_envs .= $macros{"$ {flavor}_$ {var}_GPTMACRO"} . " ";
    $me->{'macrolist'}->{"$ {var}_GPTMACRO"}++;
  }

  $macros{"$ {flavor}_CORE_CONFIG_GPTMACRO"} = $core_switches;
  $macros{"$ {flavor}_CORE_ENV_GPTMACRO"} = $core_envs;
  $me->{'already_done'}->{$flavor}++;
  return \%macros;
}

sub macrolist {
  my ($me, %args) = @_;
  return [ keys %{$me->{'macrolist'}}];
}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;

__END__
