package Grid::GPT::BaseNode;

use strict;
use Carp;

require Exporter;
require Grid::GPT::DepNode;
require Grid::GPT::GPTObject;

use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::GPTObject);

sub new {
  my ($that, %arg)  = @_;
  my $class = ref($that) || $that;
  my $self  = {
               depnode => $arg{'depnode'},# This needs to move to DepNode.
               pkgname => undef,
               flavor => undef,
               pkgtype => undef,
	      };
  bless $self, $class;
  $self->_init(%arg);
  return $self;
}

sub _add_deptype{
  my($me,$att) = @_;
  $me->{'deptype'} = $att;
}
sub _add_pkgname{
  my($me,$att) = @_;
  $me->{'pkgname'} = $att;
}
sub _add_flavor{
  my($me,$att) = @_;
  $me->{'flavor'} = $att;
}
sub _add_pkgtype{
  my($me,$att) = @_;
  $me->{'pkgtype'} = $att;
}
sub _add_versions{
  my($me,$att) = @_;
  $me->{'versions'} = $att;
}

sub printnode {
  my($me) = @_;

  print "$me->{'pkgname'}-";
  print "$me->{'flavor'}-" if defined $me->{'flavor'};
  print "$me->{'pkgtype'}\n";

}
sub formnode {
  my($me) = @_;

  return $me->label();
}

sub label {
  my($me) = @_;
  my $result = "$me->{'pkgname'}-";
  $result .="$me->{'flavor'}-" if defined $me->{'flavor'};
  $result .="$me->{'pkgtype'}";

  return $result;
}

sub is_same {
  my ($me, $other) = @_;

  return 0 if $me->pkgname() ne $other->pkgname();
  return 0 if $me->flavor() ne $other->flavor();

#This hack is to compensate for GPT labeling a noflavor pkg pgm_static
  return 0 if $me->pkgtype() ne $other->pkgtype() 
    and ! ( $me->pkgtype() =~ m!pgm! and 
            $other->pkgtype() =~ m!pgm! );

  return 0 if $me->flavor() ne 'noflavor' 
    and $me->pkgtype() ne  $other->pkgtype()
      and $me->pkgtype() =~ m!pgm! 
        and $other->pkgtype() =~ m!pgm!;

  return 0 if $me->pkgtype() ne $other->pkgtype() 
    and $me->pkgtype() !~ m!pgm!;

  return 1;
}


sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
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

Grid::GPT::BaseDependency - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::BaseDependency;
  my $dep = new Grid::GPT::BaseDependency(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::BaseDependency> is used to encapsulate a dependency
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

Create a new I<Grid::GPT::BaseDependency> object.  The function has the following named objects:

=over 4

=item versions

Reference to an array of L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> objects.

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

Adds dependency contents into an L<Grid::GPT::XML|Grid::GPT::XML> object. 


=item convert_dependency_hash2xml(dependency_hash_reference, xml_obj)

Class function which adds the contents of all dependency objects in a
hash reference to an L<Grid::GPT::XML|Grid::GPT::XML> object.

=item create_dependency_hash(xml_obj, package_type_of_dependency_owner)

This is a class function which creates a hash of
I<Grid::GPT::BaseDependency> objects out of an
L<Grid::GPT::XML|Grid::GPT::XML> object.  The key to each hash entry
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
