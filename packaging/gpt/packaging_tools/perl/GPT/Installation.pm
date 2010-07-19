package Grid::GPT::Installation;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::DepNode;
use Data::Dumper;
require Grid::GPT::PkgSet;
require Grid::GPT::PackageFactory;
require Grid::GPT::FilelistFunctions;
require Grid::GPT::PkgMngmt;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::PkgSet);

sub _init
{
    my ($me, %args)  = @_;

    $me->{'locations'} = $args{'locations'};
    $me->{'locations'} = new Grid::GPT::Locations() if ! defined $args{'locations'};
$me->{'locations'}->{'installdir'} = $args{'pkgdir'} if defined $args{'pkgdir'};
    $me->{'with_filelists'} = $args{'with_filelists'};

    $me->{'disable_version_checking'} = $args{'disable_version_checking'};
    $me->{'enable_version_checking'} = $args{'enable_version_checking'};
    $me->Grid::GPT::PkgSet::_init(%args);
    $me->{'deps'} = $args{'deps'};
    $me->{'root_package'} = $args{'root_package'};
    $me->{'dep_packages'} = $args{'dep_packages'};
    $me->load_installation() if !defined $args{'noload'};
    $me->load_core() if defined $args{'core_only'};
}

sub load_core
{ 
  my ($me, %args) = @_;
  
  my $dirtype = defined $args{'dir'} ? $args{'dir'} : 'pkgdir';
  $me->import_package_dir("globus_core", $dirtype);
}

sub load_installation
{
  my ($me, %args) = @_;

  my $dirtype = defined $args{'dir'} ? $args{'dir'} : 'pkgdir';

  my @pkgdirs;
  my $root_package = $me->{'root_package'}->Name() if defined $me->{'root_package'};
  
  if ( defined $root_package ) {
      my %hash;
      # Required to check for rebuilds.
      $me->import_package_dir($root_package, $dirtype);
      $hash{"$root_package"} = 1;

      foreach my $key ( @$me{'dep_packages'} ) {
         foreach my $bar ( @$key ) {
            push @pkgdirs, $bar;
         }
      }

      $me->import_deps($dirtype, \%hash, @pkgdirs) if $me->{'deps'};
  } else {
      opendir(PKGDIR, $me->{'locations'}->{$dirtype});
      my @pkgdirs = grep {$_ ne 'setup'} grep { ! m!^\.! }readdir PKGDIR;
      closedir PKGDIR;

      # Check to see if version checking is disabled for this location.
      my $gptdir = $me->{'locations'}->{'pkgdir'};
      $gptdir =~ s!globus_packages!gpt!;
##      $gptdir =~ s!gpt/packages!gpt!;

      $me->{'disable_version_checking'} = 1 
        if -e "$gptdir/disable_version_checking" 
          and ! defined $me->{'enable_version_checking'};

      for my $pd (@pkgdirs) {
        $me->import_package_dir($pd, $dirtype);
      }
  }
}

sub import_package_dir {
    my ($me, $pd, $dirtype) = @_;

    my %deparray = ();

    my $dir = "$me->{'locations'}->{$dirtype}/$pd";
    opendir(PKGDIR, $dir);
    my @pkgfiles = grep { m!\.gpt$! } readdir PKGDIR;
    closedir PKGDIR;
    my $factory = new Grid::GPT::PackageFactory;


    for my $p(@pkgfiles) {
      my $file = "$dir/$p";
      next if ( ! -f "$file" );
#      print "Scanning $file: ";
      my $pkg = $factory->type_of_package($file);
      $pkg->{'disable_version_checking'} = $me->{'disable_version_checking'};
      $pkg->read_metadata_file($file);

      my $node = $me->add_package(
                                  pkg => $pkg,
                                  with_filelists => $me->{'with_filelists'},
                                  context => "installdir",
                                  contextData => { dir => $me->{'locations'}->{'installdir'}, },
                                  convert => 0,
                                 );

# Add dependent packages to the list of packages to load.
       my @deptypes = ( 'Compile', 'Build_Link', 'Runtime_Link' );
       for my $dt ( @deptypes ) {
          my @deps = @{$node->{'depindexes'}->query( deptype=>$dt )};
          foreach my $foo (@deps) {
             #print "\t" . $foo->{'pkgname'} . "\n";
             #push @deparray, $foo->{'pkgname'};
             $deparray{$foo->{'pkgname'}} = 1;
          }
      }

      next if $dirtype eq 'setupdir';

      my $format = 
        Grid::GPT::PkgMngmt::pkg_format_file
            (pkgdir => $me->{'locations'}->{'pkgdir'}, 
             mode => 'READ',
             pkg => $node);

      $node->set_format($format);


#      $node->printnode();

#      $me->printtable();
    }

   return %deparray;
}

sub import_deps {
  my ($me, $dirtype, $bighash, @pkgdirs) = @_;
  my %new_deps;
  my %new_call;

  for my $pack ( @pkgdirs ) {
      $bighash->{$pack} = 1;
      %new_deps = $me->import_package_dir($pack, $dirtype);
      for my $bar ( keys %new_deps ) {
         if ( $bighash->{$bar} ne 1)
         {
            $bighash->{$bar} = 1;
            $new_call{$bar} = 1;
         }
      }

  }

  if ( %new_call ) {
     $me->import_deps($dirtype, $bighash, (keys %new_call))
  }
}


sub add_files {
  my ($me, $node) = @_;

  for my $f(@{($node->filelist())}) {
    if (defined $me->{'files'}->{$f}) { 
      $me->{'fileconflicts'}->{$f} = [] 
        if ! defined $me->{'fileconflicts'}->{$f};
      push @{$me->{'fileconflicts'}->{$f}}, ($node, $me->{'files'}->{$f});
      next;
    }
    $me->{'files'}->{$f} = $node;
  }

}

sub add_package {
  my ($me, %args) = @_;

  $me->Grid::GPT::PkgSet::add_package(%args);
}

sub setup_pkgs {
  my $me = shift;
  return $me->query(nodesub => sub { my $p = shift; 
                                 return defined $p->Setup_Name(); });
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
