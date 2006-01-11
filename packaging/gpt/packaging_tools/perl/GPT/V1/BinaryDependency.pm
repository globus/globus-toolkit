package Grid::GPT::V1::BinaryDependency;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::Version;
require Grid::GPT::V1::BaseDependency;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::V1::BaseDependency);

# initialize package globals, first exported ones
%binary_dependencies =
(
 'pgm'=> [ 'Runtime', 'Runtime_Link'],
 'pgm_static'=> ['Runtime', 'Regeneration'],
 'dev'=> ['Compile', 'Build_Link','Runtime'],
 'data'=> ['Runtime'],
 'doc'=> ['Runtime'],
 'rtl'=> ['Runtime', 'Runtime_Link']        
	
);


sub _init {
  my ($self, %arg)  = @_;
  $self->{'my_pkg_type'} = $arg{'my_pkg_type'};
  $self->{'flavor'} = $arg{'flavor'};

  # array of indexable fields 
  # for DependencyIndexes.pm
  $self->{'index'} = ['name', 'type', 'pkg_type', 'my_pkg_type'];
}

sub fulfills_dependency {
  my ($self, $name, $version, $pkg_type) = @_;

  return undef if $name ne $self->{'name'};

  if ($self->{'pkg_type'} eq 'pgm' or $self->{'pkg_type'} eq 'pgm_static') {
    return undef if $pkg_type ne 'pgm' and $pkg_type ne 'pgm_static';
  } else {
    return undef if $pkg_type ne $self->{'pkg_type'};
  }

  for my $v (@{$self->{'versions'}}) {
    my $result = $version->is_compatible($v);
    return $v if $result;
  }
  return undef;
}

sub validate {
  my ($self) = @_;

  die "ERROR: Dependency needs a name\n" if ! defined $self->{'name'};
  die "ERROR: Dependency $self->{'name'} needs to know its package type\n" 
    if ! defined $self->{'my_pkg_type'};

  die "ERROR: Dependency $self->{'name'} needs to have at least one version\n" 
    if @{$self->{'versions'}} == 0;

  my $deps_supported = 0;
  for my $d (@{$binary_dependencies{$self->{'my_pkg_type'}}}) {
    if ($d eq $self->{'type'}) {
      $deps_supported++;
      last;
    }
  }
  die "ERROR: Dependency $self->{'name'} of type $self->{'pkg_type'} does not support dependency type $self->{'type'}\n" if ! $deps_supported;
  
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

Grid::GPT::V1::BinaryDependency - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::V1::BinaryDependency;
  my $dep = new Grid::GPT::V1::BinaryDependency(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::V1::BinaryDependency> is used to encapsulate a dependency
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

Create a new I<Grid::GPT::V1::BinaryDependency> object.  The function has the following named objects:

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

Adds dependency contents into an L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object. 


=item convert_dependency_hash2xml(dependency_hash_reference, xml_obj)

Class function which adds the contents of all dependency objects in a
hash reference to an L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object.

=item create_dependency_hash(xml_obj, package_type_of_dependency_owner)

This is a class function which creates a hash of
I<Grid::GPT::V1::BinaryDependency> objects out of an
L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object.  The key to each hash entry
is of the form <name>_<pkg_type>.

=back

=head1 ToDo

=over 4

=item The internal validate function has not been tested. 

=back

=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::V1::XML(1) Grid::GPT::V1::Version(1).

=cut
