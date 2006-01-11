package Grid::GPT::V1::BaseDependency;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::Version;
require Grid::GPT::V1::BinaryDependency;
require Grid::GPT::V1::SourceDependency;
require Grid::GPT::DepIndexes;
use Grid::GPT::GPTObject;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::GPTObject);

sub add_xml_to {
  my (%args) = @_;
  my ($obj, $my_pkg_type, $flavor, $depindexes) = ($args{'xml'}, 
                                                 $args{'my_pkg_type'}, 
                                                 $args{'flavor'}, 
                                                 $args{'depindexes'});
  die "ERROR: Grid::GPT::V1::XML object does not contain Dependencies\n"
    if $obj->{'name'} !~ m!_Dependencies!;


  my $depname = "Grid::GPT::V1::BinaryDependency";
  $depname = "Grid::GPT::V1::SourceDependency" 
    if $obj->{'name'} =~ m!Source!;
  
  my $type = $obj->{'attributes'}->{'Type'};
  my $deps = $obj->{'contents'};
  for my $d (@$deps) {
    next if ref($d) ne 'HASH';
    my $name = $d->{'attributes'}->{'Name'};
    my $pkg_type = $d->{'attributes'}->{'Package'};
    my $xml_vers = $d->{'contents'};
    my $versions;
    for my $v (@$xml_vers) {
      next if ref($v) ne 'HASH';
      $versions = Grid::GPT::V1::Version::create_version_list($v);
      last;
    }
    die "ERROR: $type dependency $name is missing a version requirement\n" 
      if ! defined $versions;
    my $dep = new $depname(versions => $versions,
                           name => $name,
                           type => $type,
                           flavor => $flavor,
                           pkg_type => $pkg_type,
                           my_pkg_type => $my_pkg_type);
    $depindexes->add_dependency(dep => $dep);
  }
}

sub get_xml_from {
  my ($depindexes, $xml, $depname) = @_;
  my $deptypes = $depindexes->get_keys("deptype");
  for my $h (@$deptypes) {
    next if $h eq "Setup";
    $xml->startTag($depname, Type => $h);
    $xml->characters("\n");
    my $deps = $depindexes->query(deptype => $h);
    for my $d (@$deps) {
      $d->{'depnode'}->write_tag($xml);
    }
    $xml->endTag($depname);
    $xml->characters("\n");
  }
}


sub get_rpm_from {
  my ($depindexes, $flavor) = @_;
  my $rpmstring;

  return undef if ! defined $depindexes;

  my $deps = $depindexes->query();
  for my $d (@$deps) {
    next if $d->deptype() eq "Setup";
    next if $d->deptype() eq "Regeneration";
    next if $d->pkgname() eq "globus_core";
    if (defined $rpmstring) {
      $rpmstring .= ", " . $d->{'depnode'}->rpm($flavor);
    } else {
      $rpmstring = $d->{'depnode'}->rpm($flavor);
    }
  }

  $rpmstring = "Requires: $rpmstring" if defined $rpmstring;
  return $rpmstring;

}


sub new {
  my ($that, %arg)  = @_;
  my $class = ref($that) || $that;
  my $self  = {
	       versions => $arg{'versions'},
	       name => $arg{'name'},
	       type => $arg{'type'},
	       pkg_type => $arg{'pkg_type'},
	      };
  bless $self, $class;
  $self->_init(%arg);
  return $self;
}

sub is_same {
  my ($me, $other) = @_;

  return 0 if $me->{'name'} ne $other->{'name'};
  return 0 if $me->{'type'} ne $other->{'type'};
  return 0 if defined $me->{'pkg_type'} and ! defined $other->{'pkg_type'};
  return 0 if ! defined $me->{'pkg_type'} and defined $other->{'pkg_type'};
  return 0 if ! defined $me->{'pkg_type'} and ! defined $other->{'pkg_type'};
  return 0 if $me->{'pkg_type'} ne $other->{'pkg_type'};
  return 1;
}

sub rpm {
  my ($self, $flavor) = @_;

  my $rpmname = "$self->{'name'}";
  $rpmname .= "_$flavor" if defined $self->{'pkg_type'} and 
    ($self->{'pkg_type'} eq 'rtl' or $self->{'pkg_type'} eq 'dev');
  $rpmname .= "_$self->{'pkg_type'}" if defined $self->{'pkg_type'};
  my $rpmstring = "";
  for my $v (@{$self->{'versions'}}) {
    $rpmstring .= " " . $v->rpm($rpmname);
  }

  return $rpmstring;
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

sub write_tag {
  my ($self, $xml) = @_;

  if (defined $self->{'pkg_type'}) {
    $xml->startTag('Dependency',Name => $self->{'name'}, 
		   Package => $self->{'pkg_type'});
  } else {
    $xml->startTag('Dependency',Name => $self->{'name'});    
  }
  $xml->characters("\n");
  Grid::GPT::V1::Version::convert_version_list2xml($self->{'versions'}, $xml);
  $xml->endTag('Dependency');
  $xml->characters("\n");
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::V1::BaseDependency - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::V1::BaseDependency;
  my $dep = new Grid::GPT::V1::BaseDependency(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::V1::BaseDependency> is used to encapsulate a dependency
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

Create a new I<Grid::GPT::V1::BaseDependency> object.  The function has the following named objects:

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
I<Grid::GPT::V1::BaseDependency> objects out of an
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
