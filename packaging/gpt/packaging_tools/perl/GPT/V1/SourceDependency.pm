package Grid::GPT::V1::SourceDependency;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS 
                  %src2bin_dependencies 
                  %src2bindepenvs 
                  %src2bin_dep_extension);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;
use Grid::GPT::V1::BinaryDependency;
require Grid::GPT::V1::BaseDependency;
use Grid::GPT::V1::Version;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::V1::BaseDependency);

# This maps source deps to the generated bin package types

%src2bin_dependencies =  (
   'compile' => {
		 pgm=> undef,
		 pgm_static=> undef,
		 dev=> 'Compile',
		 data=> undef,
		 doc=> undef,
		 rtl=> undef
		},
   'pgm_link' => {
		  pgm=> 'Runtime_Link',
		  pgm_static=> 'Regeneration',
		  dev=> undef,
		  data=> undef,
		  doc=> undef,
		  rtl=> undef
		 },
   'lib_link' => {
		  pgm=> undef,
		  pgm_static=> undef,
		  dev=> 'Build_Link',
		  data=> undef,
		  doc=> undef,
		  rtl=> 'Runtime_Link'
		 },
   'data_runtime' => {
		      pgm=> undef,
		      pgm_static=> undef,
		      dev=> undef,
		      data=> 'Runtime',
		      doc=> undef,
		      rtl=> undef
		     },
   'doc_runtime' => {
		     pgm=> undef,
		     pgm_static=> undef,
		     dev=> undef,
		     data=> undef,
		     doc=> 'Runtime',
		     rtl=> undef
		    },
   'lib_runtime' => {
		     pgm=> undef,
		     pgm_static=> undef,
		     dev=> 'Runtime',
		     data=> undef,
		     doc=> undef,
		     rtl=> 'Runtime'
		    },
   'pgm_runtime' => {
		     pgm=> 'Runtime',
		     pgm_static=> 'Runtime',
		     dev=> undef,
		     data=> undef,
		     doc=> undef,
		     rtl=> undef
		    },
   
  );

%src2bindepenvs =  (
   'compile' => {
		 Runtime => undef,
		 Build => 'Compile',
		},
   'pgm_link' => {
		  Runtime => 'Runtime_Link',
		  Build => undef,
		 },
   'lib_link' => {
		  Build=> 'Build_Link',
		  Runtime => 'Runtime_Link'
		 },
   'data_runtime' => {
                      Runtime => 'Runtime',
                      Build => undef,
		     },
   'doc_runtime' => {
                      Runtime => 'Runtime',
                      Build => undef,
		    },
   'lib_runtime' => {
                      Runtime => 'Runtime',
                      Build => undef,
		    },
   'pgm_runtime' => {
                      Runtime => 'Runtime',
                      Build => undef,
		    },
   
  );

{
  my %binpackages2src_dependencies;

  sub binpkg2deps {
    my ($pkg) = @_;
    _init_binpkg2deps() if ! defined $binpackages2src_dependencies{$pkg};
    return $binpackages2src_dependencies{$pkg};
  }

  sub _init_binpkg2deps {
    while (my ($srcdep,$srchash) = each %src2bin_dependencies) {
      while (my ($pkg,$bindep) = each %$srchash){
        $binpackages2src_dependencies{$pkg} = [] 
          if ! defined $binpackages2src_dependencies{$pkg};
        push @{$binpackages2src_dependencies{$pkg}}, $srcdep;
      }
    }
  }
}

sub get_bindeps_from {
  my ($depindexes, $pkgtype, $flavor) = @_;

  my $bindeps = new Grid::GPT::DepIndexes;

  my $binsrcdeps = binpkg2deps($pkgtype);

  for my $srcd(@$binsrcdeps) {
    my $deps = $depindexes->query(deptype => $srcd);
    for my $d (@$deps) {
      my $bd = $d->{'depnode'}->convert($pkgtype, $flavor);
      next if ! defined $bd;
      $bindeps->add_dependency(dep => $bd);
    }
  }

  return $bindeps;
}

sub _init {
  my ($self, %arg)  = @_;
  $self->{'index'} =['name', 'type', 'pkg_type'];
  }

sub fulfills_dependency {
  my ($self, $name, $version, $pkg_type) = @_;

  return undef if $name ne $self->{'name'};
  my $bin_dep_pkg_type = $self->src2bin_dep_extension($pkg_type);
  if ($bin_dep_pkg_type eq 'pgm' or $bin_dep_pkg_type eq 'pgm_static') {
    return undef if $pkg_type ne 'pgm' and $pkg_type ne 'pgm_static';
  } else {
    return undef if $pkg_type ne $bin_dep_pkg_type;
  }

  for my $v (@{$self->{'versions'}}) {
    my $result = $version->is_compatible($v);
    return $v if $result;
  }
  return undef;
}

sub convert {
  my ($self, $bin_pkg_type, $flavor) = @_;
  my $bindep = $src2bin_dependencies{$self->{'type'}}->{$bin_pkg_type};
  my $bindep_pkg_type = $self->src2bin_dep_extension($bin_pkg_type);
  return undef if ! defined $bindep;

  $flavor='noflavor' if $bindep_pkg_type ne 'rtl' and 
    $bindep_pkg_type ne 'dev'; 

  return new Grid::GPT::V1::BinaryDependency(versions => $self->{'versions'}, 
					 name => $self->{'name'},
					 flavor => $flavor,
					 type => $bindep,
					 pkg_type => $bindep_pkg_type,
					 my_pkg_type => $bin_pkg_type);

}

sub src2bindep {
    my ($self, $depenv) = @_;
    return $src2bindepenvs{$self->{'type'}}->{$depenv};
}

sub validate {
  my ($self) = @_;

  die "ERROR: Dependency needs a name\n" if ! defined $self->{'name'};

  die "ERROR: Dependency $self->{'name'} needs to have at least one version\n" 
    if @{$self->{'versions'}} == 0;

}

# This shows which src dep types have package types automatically
sub src2bin_dep_extension {
  my ($self, $my_pkg_type) = @_;
  my ($dep, $pkg_type) = ($self->{'type'}, $self->{'pkg_type'});

  return $pkg_type if defined $pkg_type;
  return 'dev' if $dep eq 'compile';
  return 'rtl' if $dep eq 'pgm_link';
  return $my_pkg_type if $dep eq 'lib_link';

  die "ERROR: Package type needs to be defined for $dep\n";
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

Grid::GPT::V1::SourceDependency - Perl extension for reading packaging metadata files

=head1 SYNOPSIS

  use Grid::GPT::V1::SourceDependency;
  my $pkg = new Grid::GPT::V1::SourceDependency;

  $pkg->read_metadata_file('src_metadata.xml');
  my $bin_pkg = $pkg->convert_metadata($type, $build_flavor);
  $bin_pkg->output_metadata_file("$ {type}_metadata.xml");

=head1 DESCRIPTION

I<Grid::GPT::V1::SourceDependency> is used to encapsulate a single
dependency found in a source package.  These dependencies are passed
on to the binary packages that are created from the source.  The
dependencies are divided into the following types:

=over 4

=item   compile

Dependency occurs when the package is used for compiling.  Usually
caused by header files including headers from other packages.  Passed
on to dev package types

=item   pgm_link

Dependency occurs when the programs created by this package were
linked.  Passed on to the pgm and pgm_static package types.

=item   lib_link

Dependency occurs when libraries created by this package are linked.
Passed on to the rtl and dev package types.


=item   data_runtime

Dependency needed during runtime by the data package.

=item   doc_runtime

Dependency needed during runtime by the doc package.

=item   lib_runtime

Dependency needed during runtime by the rtl and dev packages.

=item   pgm_runtime

Dependency needed during runtime by the pgm and pgm_static packages.

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::V1::SourceDependency> object.  The function has
the following named objects:

=over 4

=item versions

Reference to an array of L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> objects.

=item name

Name of the dependent package.

=item type

The type of dependency.

=item pkg_type

The binary package type of the dependent package.

=back

=item fulfills_dependency(name, version)

Returns a 1 if the arguments met the requirements of the
dependency. Returns a 0 if not.


=item convert(binary_package_type)

Converts the dependency to a
L<Grid::Grid::BinaryDependency|Grid::Grid::BinaryDependency> object.

=item create_dependency_hash

This is a class function which creates a hash of
I<Grid::GPT::V1::SourceDependency> objects out of an
L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object.

=back




=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::V1::BinaryDependency(1) Grid::GPT::V1::XML(1) Grid::GPT::V1::Version(1).

=cut
