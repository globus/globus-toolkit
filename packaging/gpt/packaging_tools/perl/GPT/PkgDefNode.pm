package Grid::GPT::PkgDefNode;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
require Grid::GPT::BaseNode;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseNode);

sub _init {
  my ($me, %args)  = @_;
  $me->{'installed'} = $args{'installed'};
  $me->_add_pkgname($args{'pkgname'});
  $me->_add_flavor($args{'flavor'});
  $me->_add_pkgtype($args{'pkgtype'});
  $me->{'version'} = $args{'version'};
  $me->{'pkgnode'} = $args{'pkgnode'};
  $me->{'log'} = $args{'log'};
  $me->{'bundle'} = defined $args{'bundle'} ? $args{'bundle'} : "NONE";

}

sub is_same {
  my ($me, $other) = @_;

  return 0 if ! $me->Grid::GPT::BaseNode::is_same($other);
  return $me->{'version'}->is_equal($other->{'version'});

}

sub matches_pkgnode {
  my ($me, $other) = @_;

# hack to overcome name differences in the node classes
  return 0 if ! $me->Grid::GPT::BaseNode::is_same($other);
  return $me->{'version'}->is_equal($other->{'depnode'}->{'Version'});

}

sub is_replacable {
  my ($me, %args) = @_;
  my ($other, $force, $loose) = ($args{'other'}, 
                                 $args{'force'}, 
                                 $args{'loose'}, 
                                );

  $me->{'log'}->debug("replacer: " .  $other->label() .  "-" . 
                      $other->version_label()  . 
                      " replacee: " . $me->label() . "-" . 
                      $me->version_label() . " " .
                     ($loose ? "LOOSE " : " ") .
                     ($force ? "FORCE " : " ")
                     );

  $me->{'log'}->debug("Testing force and pkg equivelence");
  # force is defined
  return "REPLACE" if defined $force 
    and $other->pkgtype() eq $me->pkgtype()
      and $other->flavor()  eq $me->flavor();

  $me->{'log'}->debug("Testing force and pgm|pgm_static");
  # force is defined
  return "REPLACE" if defined $force 
    and $other->pkgtype()  =~ m!pgm! and
      $me->pkgtype() =~ m!pgm!;

  $me->{'log'}->debug("Testing replacement is older");
  # old is newer than new
  return "DOWNGRADE" 
    if $me->is_newer($other) 
    and $other->pkgtype() eq $me->pkgtype()
      and $other->flavor()  eq $me->flavor();

  # new and old are the same flavor and pkgtype and new is newer

  $me->{'log'}->debug("Testing replacement is newer and the same");
  return "REPLACE" 
    if $other->is_newer($me) 
      and $other->pkgtype() eq $me->pkgtype()
      and $other->flavor()  eq $me->flavor();

  # new and old are the same version, flavors are the same, 
  # flavors are not noflavor and pkgtype of old is pgm_static

  $me->{'log'}->debug("Testing pkg are exactly the same and the replacee is pgm_static");

  return "REPLACE" 
    if $other->{'version'}->is_equal($me->{'version'}) 
      and $me->pkgtype() eq 'pgm_static'
      and $other->pkgtype() =~ m!pgm!
      and $other->flavor()  eq $me->flavor()
      and $other->flavor()    ne 'noflavor';

  # new and old are the same version, 
  # flavors are equal, pkgtypes are equal

  $me->{'log'}->debug("Testing replacement is identical");

  return "DO_NOT_INSTALL" 
    if $other->{'version'}->is_equal($me->{'version'}) 
      and $me->pkgtype() eq $other->pkgtype()
        and $other->flavor()  eq $me->flavor();

  # ignore if same package is pgm or pgm_static and flavor is noflavor

  $me->{'log'}->debug("Testing packages are pgm|pgm_static and flavor is 'noflavor'");

  return "IGNORE"
    if $me->pkgtype() =~ m!pgm! and $other->pkgtype() =~ m!pgm! 
      and $me->flavor() eq 'noflavor' and $other->flavor() eq 'noflavor';

  # Do not install if same package pgm or pgm_static and different flavors
  # and the loose flag is set.

  $me->{'log'}->debug("Testing packages are the same version, pgm|pgm_static, and loose is set");

  return "DO_NOT_INSTALL"
    if $other->{'version'}->is_equal($me->{'version'}) and 
      $me->pkgtype() =~ m!pgm! and 
        $other->pkgtype() =~ m!pgm! and $loose;

  # conflict if same package pgm or pgm_static and different flavors (this will also catch
  # pgm|pgm_static that are different versions during a "loose" state

  $me->{'log'}->debug("Testing packages are pgm|pgm_static and flavors are different");

  return "DOWNGRADE"
    if $me->pkgtype() =~ m!pgm! and $other->pkgtype() =~ m!pgm! and
    $me->is_newer($other) and $other->flavor()  eq $me->flavor();

  return "CONFLICT"
    if $me->pkgtype() =~ m!pgm! and $other->pkgtype() =~ m!pgm!;


  # packages can be colocated

  $me->{'log'}->debug("Testing packages are colocatable libraries");

  return "ADD"
    if ($me->pkgtype() eq 'rtl' or $me->pkgtype() eq 'dev') and 
      ($other->pkgtype() eq 'rtl' or $other->pkgtype() eq 'dev')
        and $other->flavor() ne $me->flavor();


  # Play it safe for unaccounted cases

  $me->{'log'}->debug("Testing cannot be determined");

  return "IGNORE";
}

sub is_newer {
  my ($me, $other) = @_;

  return $me->{'version'}->is_newer($other->{'version'});

}

sub name {
  my ($me) = @_;

  return $me->{'pkgname'};

}

sub version_label {
  my ($me) = @_;

  return $me->{'version'}->label();
}
sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an obj";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in obj of class $type";
  } 
  if (@_) {
    return $self->{$name} = shift;
  } else {
    return $self->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
