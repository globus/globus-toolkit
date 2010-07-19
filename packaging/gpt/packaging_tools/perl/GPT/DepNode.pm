package Grid::GPT::DepNode;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
require Grid::GPT::BaseNode;
use Grid::GPT::V1::Version;
use Grid::GPT::V1::BinaryDependency;
use Grid::GPT::V1::SourceDependency;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseNode);

sub _init {
  my ($me, %args)  = @_;
  $me->{'versions'} = undef;
  $me->{'deptype'} = undef;
  $me->{'disable_version_checking'} = 
    $args{'disable_version_checking'};

  $me->_add_pkgname($args{'name'}) if defined $args{'name'};
  $me->_add_flavor($args{'flavor'}) if defined $args{'flavor'};
  $me->_add_pkgtype($args{'pkgtype'}) if defined $args{'pkgtype'};
  $me->{'versions'} = $args{'versions'} if defined $args{'versions'};

  return if ! defined $args{'depnode'};

  $me->_v1bindep($args{'depnode'}) 
    if ref($args{'depnode'}) eq 'Grid::GPT::V1::BinaryDependency';
  $me->_v1srcdep($args{'depnode'}) 
    if ref($args{'depnode'}) eq 'Grid::GPT::V1::SourceDependency';
  $me->_GPTsrcdep($args{'depnode'}) 
    if ref($args{'depnode'}) eq 'Grid::GPT::GPTSourceDependency';
  $me->_GPTsrcdep($args{'depnode'}) 
    if ref($args{'depnode'}) eq 'Grid::GPT::GPTBinaryDependency';
}


sub _v1bindep {
  my ($me, $obj)  = @_;
  $me->_add_deptype($obj->type());
  $me->_add_pkgname($obj->name());
  $me->_add_flavor($obj->flavor());
  $me->_add_pkgtype($obj->pkg_type());
  $me->{'versions'} = $obj->versions();


}

sub _v1srcdep {
  my ($me, $obj)  = @_;
  $me->_add_deptype($obj->type());
  $me->_add_pkgname($obj->name());

  my $pkgtype = $obj->pkg_type();

  my %srcdep2binpkgtype = (
                           compile => 'dev',
                           pgm_link => 'dev',
                           lib_link => 'dev',
                           Setup => 'pgm',
                          );

  if (! defined $pkgtype) {
    if (defined $srcdep2binpkgtype{$obj->type()}) {
      $pkgtype =  $srcdep2binpkgtype{$obj->type()};
    } else {
      $pkgtype = 'ANY';
    }
  }

  $me->_add_pkgtype($pkgtype);
  $me->_add_flavor('ANY');
  $me->{'versions'} = $obj->versions();
}

sub _GPTbindep {
  my ($me, $obj)  = @_;
  $me->_add_deptype($obj->type());
  $me->_add_pkgname($obj->name());
  $me->_add_flavor($obj->flavor());
  $me->_add_pkgtype($obj->pkg_type());
  $me->{'versions'} = $obj->versions();
}

sub _GPTsrcdep {
  my ($me, $obj)  = @_;
  $me->_add_deptype($obj->type());
  $me->_add_pkgname($obj->name());
  $me->_add_pkgtype($obj->pkg_type());
  $me->{'versions'} = $obj->versions();
}

sub is_same {
  my ($me, $other) = @_;

  return $me->{'depnode'}->is_same($other->{'depnode'});

}

sub is_compatible {
  my ($me, $pkgversion) = @_;

  return 1 if defined $me->{'disable_version_checking'};

  for my $v (@{$me->{'versions'}}) {
    return 1 if $v->is_compatible($pkgversion);
  }
  return 0;
}

sub label {
  my($me, %args) = @_;
  my $result = "$me->{'deptype'}-" . $me->Grid::GPT::BaseNode::label();

  return $result if ! defined $args{'versions'};

  $result .= " Ver Reqs: ";
  for my $v (@{$me->{'versions'}}) {
    $result .= $v->label() . " ";
  }
  return $result;
}

sub printnode {
  my($me) = @_;

  print "/deptype=$me->{'deptype'}->";
  $me->Grid::GPT::BaseNode::printnode();
}

sub formnode {
  my($me) = @_;

  return $me->label();
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
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::DepNode - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::DepNode;
  my $dep = new Grid::GPT::DepNode(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::DepNode> is used to encapsulate a dependency
that one binary package has to another dependency.  These dependencies
are seperated into the following types:

=over 4

=item Compile

Dependency occurs when the package is used for compiling.  Usually
caused by header files including headers from other packages.

=item Build_Link

Dependency occurs when the package is linked to other applications.
This commonly known as dependent libraries.  

=item Regeneration

Dependency occurs when a statically built package needs to be rebuilt
because of updates to dependent packages.  This results in a new
binary package even though nothing inside the package has changed and
the version number has not been updated.

=item Runtime_Link

Dependency occurs when a package needs to load another package's binary at run-time.

=item Runtime

Dependency occurs when a package needs to read a file or execute a
program from another package.

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::DepNode> obj.  The function has the following named objs:

=over 4

=item versions

Reference to an array of L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> objs.

=item name

Name of the dependent package.

=item type

The type of dependency.

=item pkg_type

The binary package type of the dependent package.

=item my_pkg_type

The binary package type of the package owning this dependency.

=back

=item fulfills_dependency(name, version, pkg_type)

Returns a 1 if the arguments met the requirements of the
dependency. Returns a 0 if not.  Note that package types pgm and
pgm_static are considered equivalent.

=item write_tag(xml_obj)

Adds dependency contents into an L<Grid::GPT::XML|Grid::GPT::XML> obj. 


=item convert_dependency_hash2xml(dependency_hash_reference, xml_obj)

Class function which adds the contents of all dependency objs in a
hash reference to an L<Grid::GPT::XML|Grid::GPT::XML> obj.

=item create_dependency_hash(xml_obj, package_type_of_dependency_owner)

This is a class function which creates a hash of
I<Grid::GPT::DepNode> objs out of an
L<Grid::GPT::XML|Grid::GPT::XML> obj.  The key to each hash entry
is of the form <name>_<pkg_type>.

=back

=head1 ToDo

=over 4

=item The internal validate function has not been tested. 

=back

=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::XML(1) Grid::GPT::V1::Version(1).

=cut
