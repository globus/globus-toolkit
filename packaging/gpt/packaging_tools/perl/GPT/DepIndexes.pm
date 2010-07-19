package Grid::GPT::DepIndexes;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::DepNode;
use Data::Dumper;
require Grid::GPT::BaseTable;
require Grid::GPT::PkgSet;
require Grid::GPT::GPTObject;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::GPTObject Grid::GPT::BaseTable);

sub _init {
  my ($me, %args)  = @_;
  $me->{'indexes'} = ['deptype', 'pkgname','flavor','pkgtype'];
  $me->{'deps'} = [];
  $me->{'disable_version_checking'} = $args{'disable_version_checking'};
}


sub query {
  my ($me, %args) = @_;
  my $list = $me->Grid::GPT::BaseTable::query(%args);

#  my @badlist = grep { ! defined $_->deptype() } @$list;

#  if (@badlist) {
#    print "+++++++++++++badlist++++++++++\n";
#    for (@badlist) {
#      $_->printnode();
#    }
#    print "+++++++++++++badlist++++++++++\n";
#  }

  my @sorted = sort { 
    (defined $a->deptype() ? $a->deptype() : $a->providetype()) cmp 
      (defined $b->deptype() ? $b->deptype() : $b->providetype()) ||
    $a->pkgname() cmp $b->pkgname() ||
    $a->flavor() cmp $b->flavor() ||
    $a->pkgtype() cmp $b->pkgtype()
  } @$list;

  return \@sorted;
}
sub add_dependency {
  my ($me, %args) = @_;
  my $object = new Grid::GPT::DepNode(depnode => $args{'dep'},
                                      name => $args{'name'},
                                      flavor => $args{'flavor'},
                                      pkgtype => $args{'pkgtype'},
                                      versions => $args{'versions'},
                                      disable_version_checking => 
                                      $me->{'disable_version_checking'});


  my $exists = $me->get_dep(depnode =>$object);
  if (defined $exists) {
    print "WARNING: DepIndexes: dependency ";
    $object->printnode();
    print "Is a duplicate of ";
      $exists->printnode();
    return;
  }
  
  $me->add_object(depnode => $object,
                  deptype => $object->deptype(),
                  pkgname => $object->pkgname(),
                  flavor => $object->flavor(),
                  pkgtype => $object->pkgtype());


  push @{$me->{'deps'}}, $object;

#$object->printnode();

}

sub add_pkgnode {
  my ($me, %args) = @_;
  my $object = $args{'depnode'};

  my $exists = $me->get_dep( deptype => $args{deptype},
                             pkgname => $args{'pkgname'},
                             flavor => $args{'flavor'},
                             pkgtype => $args{'pkgtype'});
  if (defined $exists) {
#    print "WARNING: DepIndexes: package ";
#    $object->printnode();
#    print "Is a duplicate of ";
#      $exists->printnode();
    return;
  }

  $me->add_object(depnode => $object,
                  deptype => $args{'deptype'},
                  pkgname => $args{'pkgname'},
                  flavor => $args{'flavor'},
                  pkgtype => $args{'pkgtype'}
                  );

  push @{$me->{'deps'}}, $object;

#$object->printnode();

}

sub get_dep {
  my ($me, %args) = @_;
  my ($deptype,
      $pkgname, 
      $flavor, 
      $pkgtype) = ($args{'deptype'} || 'ANY', 
                   $args{'pkgname'} || 'ANY', 
                   $args{'flavor'} || 'ANY',
                   $args{'pkgtype'} || 'ANY',
                   );

  if (defined $args{'depnode'}) {
    my @deps = grep {$_->is_same($args{'depnode'}) } @{$me->{'deps'}};
    return $deps[0];
  }

#  if (defined $args{'depnode'}) {
#    print "Getting: ";
#    $args{'depnode'}->printnode();
#  }
  return undef if ! defined $me->{'table'}->{$deptype};
  return undef if ! defined $me->{'table'}->{$deptype}->{$pkgname};
  return undef 
    if ! defined $me->{'table'}->{$deptype}->{$pkgname}->{$flavor};  
  return $me->{'table'}->{$deptype}->{$pkgname}->{$flavor}->{$pkgtype};  
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

Grid::GPT::DepIndexes - Perl extension for indexing package dependency metadata

=head1 SYNOPSIS

  use Grid::GPT::DepIndexes;
  my $pkg = new Grid::GPT::DepIndexes;

  $pkg->read_metadata_file('src_metadata.xml');
  my $bin_pkg = $pkg->convert_metadata($type, $build_flavor);
  $bin_pkg->output_metadata_file("$ {type}_metadata.xml");

=head1 DESCRIPTION

I<Grid::GPT::DepIndexes> is used to encapsulate a single
dependency found in a source package.  These dependencies are passed
on to the binary packages that are created from the source.  The
dependencies are divided into the following types:

=over 4

=item   compile

Dependency occurs when the package is used for compiling.  Usually
caused by header files including headers from other packages.  Passed
on to hdr and dev package types

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

Create a new I<Grid::GPT::DepIndexes> object.  The function has
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
I<Grid::GPT::DepIndexes> objects out of an
L<Grid::GPT::XML|Grid::GPT::XML> object.

=back




=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::BinaryDependency(1) Grid::GPT::XML(1) Grid::GPT::V1::Version(1).

=cut
