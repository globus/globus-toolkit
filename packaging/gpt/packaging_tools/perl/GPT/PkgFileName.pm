package Grid::GPT::PkgFileName;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Grid::GPT::V1::BuildFlavors;
use Grid::GPT::V1::Definitions;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter);


sub new {
  my ($that, %args)  = @_;
  my $class = ref($that) || $that;
  my $me  = {
             locations => $args{'locations'},
             flavors => ['noflavor'],
            };
  bless $me, $class;
  $me->_init(%args);
  return $me;
}


sub _init {
  my ($me, %args) = @_;
  my $coreflavors = new Grid::GPT::V1::BuildFlavors(core =>1);
  push @{$me->{'flavors'}}, @{$coreflavors->{'flavors'}};

  if (-d "$me->{'locations'}->{'installdir'}/etc/globus_core") {
    my $installedflavors = new Grid::GPT::V1::BuildFlavors(installed => 1,
                                                           locations => 
                                                           $me->{'locations'});
    push @{$me->{'flavors'}}, @{$installedflavors->{'flavors'}};
  }

}

sub flavor_exists {
  my ($me, $flavor) = @_;
  return 1 if $flavor eq 'ANY';
  my $result =  grep {$_ eq $flavor } @{$me->{'flavors'}};
  return $result;
  }


sub parse_name {
  my ($me,$name) = @_;
  my @threepiece;

# Check for the form name-flavor_pkgtype
my @pieces;
if( $name  =~  m!(.+)-pgm_static! )
{ 
  @pieces = $name  =~  m!(.+)-([^_]+)-(.+)!;
}
else
{
  @pieces = $name  =~  m!(.+)-([^_]+)_(.+)!;
}
##  my @pieces = $name  =~  m!(.+)-([^_]+)-(.+)!;

  @threepiece = @pieces if @pieces == 3;

  if (! @threepiece) {

    my @pieces = split /-/, $name;

    if (@pieces > 3) {
      my $count = 2;
      for my $p (reverse @pieces) {

        if ($count > 0) {
          $threepiece[$count] = $p;
          $count--;
          next;
        }

        if (defined $threepiece[0]) {
          $threepiece[0] = "$p-" . $threepiece[0];
        } else {
          $threepiece[0] = "$p";
        }
        
      }
    } else {
      @threepiece = @pieces;
    }
  }

# Replace '*' and undefined elements with 'ANY'
  for my $i (0..2) {
    my $item = $threepiece[$i];
    $threepiece[$i] = defined $item ? $item : 'ANY';
    $item = $threepiece[$i];
    $threepiece[$i] = $item eq '*' ? 'ANY' : $item;
  }

  my $result =  {
          pkgname => $threepiece[0],
          flavor => $threepiece[1],
          pkgtype => $threepiece[2],
         };

# Check to make sure the pkgtype is valid
  if (! grep { $_ eq $result->{'pkgtype'}} 
      @Grid::GPT::V1::Definitions::package_types, 'ANY') {

    $result->{'pkgname'} .= "-$result->{'flavor'}";
    $result->{'flavor'} = $result->{'pkgtype'};
    $result->{'pkgtype'} = 'ANY';
  }

# Check to make sure the flavor is valid
  if (! $me->flavor_exists($result->{'flavor'})) {

    $result->{'pkgname'} .= "-$result->{'flavor'}";
    $result->{'flavor'} = 'ANY';

  }
  return $result;
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
