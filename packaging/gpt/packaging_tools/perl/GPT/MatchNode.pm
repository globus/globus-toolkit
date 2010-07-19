package Grid::GPT::MatchNode;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
require Grid::GPT::BaseNode;
require Grid::GPT::DepIndexes;
use Grid::GPT::V1::Version;
use Grid::GPT::V1::BinaryDependency;
use Grid::GPT::V1::SourceDependency;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseNode);

my %depenv2deptypes = (
                       Setup => ['Setup'],
                       BuildStatic => ['Compile', 'Build_Link'],
                       Build => ['Compile', 'Build_Link', 'Runtime_Link'],
                       BuildandSetup => ['Compile', 
                                         'Build_Link', 
                                         'Runtime_Link', 
                                         'Setup'],
                       BuildStaticandSetup => ['Compile', 
                                         'Build_Link', 
                                         'Setup'],
                       RuntimeStatic => ['Runtime'],
                       Runtime => ['Runtime','Runtime_Link'],
                       RuntimeandSetup => ['Runtime','Runtime_Link', 'Setup'],
                       RuntimeStaticandSetup => ['Runtime','Setup'],
                      );

my %bin2srcdeptypes =  (
                    'Compile' => ['compile'],
                    'Runtime_Link' => ['pgm_link','lib_link'],
                    'Build_Link' => ['pgm_link','lib_link'],
                    'Runtime' => ['data_runtime',
                                  'doc_runtime',
                                  'lib_runtime',
                                  'pgm_runtime' ],
                    'Setup' => ['Setup'],
                      );

sub _init {
  my ($me, %args)  = @_;

  $me->{'frompkg'} = $args{'frompkg'};
  $me->{'topkg'} = $args{'topkg'};
  $me->{'dep'} = $args{'dep'};
  $me->{'dups'} = $args{'dups'};

  $me->_add_deptype(defined $args{'deptype'} ? 
                    $args{'deptype'} : $me->{'dep'}->deptype());
  $me->_add_pkgname(defined $args{'pkgname'} ? 
                    $args{'pkgname'} : $me->{'dep'}->pkgname());
  $me->_add_flavor(defined $args{'flavor'} ? 
                   $args{'flavor'} : $me->{'dep'}->flavor());
  $me->_add_pkgtype(defined $args{'pkgtype'} ? 
                    $args{'pkgtype'} : $me->{'dep'}->pkgtype());
}

sub is_same {
  my ($me, $other) = @_;

  return 0 if ! $me->{'frompkg'}->is_same($other->{'frompkg'});
  return 0 if ! $me->{'dep'}->is_same($other->{'dep'});
  $me->{'topkg'}->is_same($other->{'topkg'});

}

sub printnode {
  my($me, %args) = @_;
  my $pretty = defined $args{'to'} ? 'to' : undef;
  $pretty = defined $args{'from'} ? 'from' : $pretty;
  if (defined $pretty) {
    if (defined $args{'html'}) {
      print $me->{"$ {pretty}pkg"}->label(href=>1), " <br>\n";
      if (defined $args{'to'}) {
        for my $m (@{$me->{'dups'}}) {
          print $m->label(href=>1), " <br>\n";
      print "<br>\n";
        }
      }
    } else {
      print $me->{"$ {pretty}pkg"}->label(), "\n";
      if (defined $args{'to'}) {
        for my $m (@{$me->{'dups'}}) {
          print $m->label(), "\n";
        }
      }
    }
    return;
  }
  print "/from=",$me->{'frompkg'}->label();
  print "/dep=",$me->{'dep'}->label();
  print "/to=",$me->{'topkg'}->label(),"/tag=";
  $me->Grid::GPT::BaseNode::printnode();
}

sub formnode {
  my($me, %args) = @_;
  my $msg = "/from=" . $me->{'frompkg'}->label();
  $msg .=  "/dep=" . $me->{'dep'}->label();
  $msg .=  "/to=" . $me->{'topkg'}->label() . "/tag=";
  $msg .= $me->Grid::GPT::BaseNode::label();
  return $msg;
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
