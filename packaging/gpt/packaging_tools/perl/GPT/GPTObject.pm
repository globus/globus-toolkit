package Grid::GPT::GPTObject;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA);

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

sub clone {
    my $self = shift;
    my $clone = $self->new();
    replicate($self, $clone);
    return $clone;
}

sub replicate {
  my ($rold, $rclone) = @_;

   return $rold if (ref(\$rold) eq 'SCALAR');
    
  if (ref($rold) eq 'ARRAY') {
      my @list;
      for my $e (@$rold)
      {
          push(@list, replicate($e));
      }
      return \@list;
  }
  
  my $rnew;

  if (ref($rold) =~ m!::!) {
    $rnew = $rclone;
    $rnew = $rold->clone() if ! defined $rnew;
  }

  $rnew = {} if (ref($rold) eq 'HASH');

  for my $e (sort keys %$rold) {
    $rnew->{$e} = replicate($rold->{$e});
  }
  return $rnew
}

sub set
{
    my($self, %args) = @_;

    if (!defined($self->{'data'}))
    {
        $self->{'data'} = {};
    }

    foreach my $k (keys %args)
    {
        if ( !$self->isLocked($k) )
        {
            $self->{'data'}->{$k} = $args{$k};
        }
    }
}

sub get
{
    my($self, $arg) = @_;

    if (!defined($self->{'data'}))
    {
        return undef;
    }

    return $self->{'data'}->{$arg};
}

sub isLocked
{
    my $self = shift;
    my($arg) = @_;

    if (!defined($self->{'locked'}))
    {
        return 0;
    }

    if (!defined($self->{'locked'}->{$arg}))
    {
        return 0;
    }

    return $self->{'locked'}->{$arg};
}

sub lock
{
    my $self = shift;
    my(@args) = @_;

    if (!defined($self->{'locked'}))
    {
        $self->{'locked'} = {};
    }

    for my $v (@args)
    {
        $self->{'locked'}->{$v} = 1;
    }

    return 1;
}

sub unlock
{
    my $self = shift;
    my(@args) = @_;

    if (!defined($self->{'locked'}))
    {
        return 1;
    }

    for my $v (@args)
    {
        delete($self->{'locked'}->{$v});
    }

    return 1;
}

sub isSet
{
    my $self = shift;
    my($arg) = @_;

    my $foo = $self->get($arg);
    if (!defined($foo))
    {
        return 0;
    }

    return 1;
}

sub isTrue
{
    my $self = shift;
    my($arg) = @_;

    my $foo = $self->get($arg);
    if (!defined($foo))
    {
        return 0;
    }

    if ($foo)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::GPTObject - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::GPTObject;
  my $dep = new Grid::GPT::GPTObject(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::GPTObject> is used to encapsulate a dependency
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

Create a new I<Grid::GPT::GPTObject> object.  The function has the following named objects:

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
I<Grid::GPT::GPTObject> objects out of an
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
