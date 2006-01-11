package Grid::GPT::BaseTable;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::DepNode;
use Data::Dumper;
#use Grid::GPT::PkgNode;
require Grid::GPT::GPTObject;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::GPTObject);

sub new {
  my ($that, %args)  = @_;
  my $class = ref($that) || $that;
  my $me  = {
               table => {},
	      };

  bless $me, $class;

  $me->_init(%args);

  return $me;
}

sub add_object {
  my ($me, %args) = @_; # arguments are the indexes and 'depnode' which should be a DepNode related object.
  my $record = $me->{'table'};
  my $errstatement = "";


  for my $i (@{$me->{'indexes'}}) {
    # set undefined indexes to "ANY"
    if (! defined $args{$i}) {
      $args{$i} = 'NONE' if ! defined $args{$i};
    } else {
      # Add index to list
      $me->{"$i-list"} = {} if ! defined $me->{"$i-list"};
      $me->{"$i-list"}->{$args{$i}} = 1;
    }
    # add to error statement
    $errstatement .= ":$args{$i}";
    # initialize the index hash if not defined
    if (! defined $record->{$args{$i}}) {
      if ($i eq $me->{'indexes'}->[-1]) {
        #object goes in the last index hash
        $record->{$args{$i}} = $args{'depnode'};
        return;
      }
      $record->{$args{$i}} = {} if ! defined $record->{$i};
    }
    # Go to next index hash
    $record = $record->{$args{$i}};
  }

  # If we wind up here something went wrong.
#  print ref($me), ": WARNING duplicate found @ $errstatement dup: ",
#    $record->label()," and ",$args{'depnode'}->label(),"\n";

}

sub query{
  my ($me, %args) = @_;
  my @matchlist;

  for my $key (@{$me->{'indexes'}}) {
    push @matchlist, defined $args{$key} ? $args{$key} : 'ANY';
  }

  my $match = shift @matchlist;
  my $list = $me->scan_hash($match);

  for my $m (@matchlist) {
    my $newlist = [];
    for my $l (@$list) {
      my $hashes = $me->scan_hash($m, $l);
      push @$newlist, @$hashes;
    }
    $list = $newlist;
  }

  if (defined $args{'nodesub'}) {
    my @list = grep { $args{'nodesub'}->($_->{'depnode'})} @$list;
    $list = \@list;
  }
  if (defined $args{'sub'}) {
    my @list = grep { $args{'sub'}->($_)} @$list;
    $list = \@list;
  }

  return $list;

}

sub scan_hash {
  my ($me, $match, $table) = @_;
  my @list;

  $table = $me->{'table'} if ! defined $table;

  while (my ($key, $record) = each (%$table)) {

    next if $match ne $key and 
      $match ne 'ANY' and 
        $key ne 'ANY';

    push @list, $record if defined $record;
  }
  return \@list;
}
		
sub get_keys {
  my ($me, $index) = @_;
  my @keys = sort keys %{$me->{"$index-list"}};
  return \@keys;
}

sub printtable {
  my ($me, %args) = @_;

  my @indexes = $me->{'indexes'};
  my $msg = $me->_recurse_form($me->{'indexes'}, $me->{'table'}, "", %args);
  print $msg;
}

sub formtable {
  my ($me, %args) = @_;
  my $msg = "";
  my @indexes = $me->{'indexes'};
  $msg .= $me->_recurse_form($me->{'indexes'}, $me->{'table'}, "", %args);
  return $msg;
}

sub _recurse_form {
  my ($me, $indexes, $table, $prtkey, %args) = @_;
  my $msg="";
  my @localindexes = @$indexes;
  my $index = shift @localindexes;

  for my $key (sort keys %$table) {
    my $record = $table->{$key};
    my $localprt = "";
    $localprt = "/$index=$key";
    if (! @localindexes) {
      $msg .= "$prtkey$localprt-> " if ! defined $args{'to'} and 
        ! defined $args{'from'};
      $msg .= $record->formnode(%args) . "\n";
    } else {
      $msg .= $me->_recurse_form(\@localindexes, 
                                 $record, 
                                 "$prtkey$localprt",
                                 %args);
    }
  }
  return $msg;
}

sub remove_package {
  my ($me, %args) = @_;

  my @indexes = $me->{'indexes'};
  $me->_recurse_remove($me->{'indexes'}, $me->{'table'}, %args);
}

sub _recurse_remove {
  my ($me, $indexes, $table, %args) = @_;
  my @localindexes = @$indexes;
  my $index = shift @localindexes;

  for my $key (sort keys %$table) {
    if (! @localindexes) {
      $table->{$key} = undef;
    } else {
      $me->_recurse_remove(\@localindexes, 
                          $table->{$key}, 
                          %args);
    }
  }
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

Grid::GPT::BaseTables - Perl extension for indexing package dependency metadata

=head1 SYNOPSIS

  use Grid::GPT::BaseTables;
  my $pkg = new Grid::GPT::BaseTables;

  $pkg->read_metadata_file('src_metadata.xml');
  my $bin_pkg = $pkg->convert_metadata($type, $build_flavor);
  $bin_pkg->output_metadata_file("$ {type}_metadata.xml");

=head1 DESCRIPTION

I<Grid::GPT::BaseTables> is used to encapsulate a single
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

Create a new I<Grid::GPT::BaseTables> object.  The function has
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
I<Grid::GPT::BaseTables> objects out of an
L<Grid::GPT::XML|Grid::GPT::XML> object.

=back




=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::BinaryDependency(1) Grid::GPT::XML(1) Grid::GPT::V1::Version(1).

=cut
