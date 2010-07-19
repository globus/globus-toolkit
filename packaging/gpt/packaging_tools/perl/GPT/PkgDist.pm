package Grid::GPT::PkgDist;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::DepNode;
use Archive::Tar;
use File::Find;

require Grid::GPT::PkgSet;
require Grid::GPT::PackageFactory;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::PkgSet);

sub _init {
  my ($me, %args)  = @_;
  
  $me->{'with_filelists'} = $args{'with_filelists'};
  $me->{'pkgdir'} = $args{'pkgdir'};
  $me->{'prefix'} = "$args{'prefix'}/" if defined $args{'prefix'};

  if (defined $args{'with_filelists'}) {
    $me->{'files'} = {};
    $me->{'fileconflicts'} = {};
  }

  $me->Grid::GPT::PkgSet::_init(%args);
  $me->load_pkgdir() if defined $args{'all'};
  $me->load_pkglist($args{'pkglist'}) if defined $args{'pkglist'};

  $me->{'pkgtars'} = $args{'pkgtars'} if defined $args{'pkgtars'};
  $me->{'prefix'} = "$args{'prefix'}/" if defined $args{'prefix'};

  $me->load_dist_from_tar();
}


sub load_pkglist {
  my ($me, $list) = @_;


  open (LIST, "$me->{'prefix'}$list");

  my @list = <LIST>;
  close LIST;
  chomp @list;
  $me->{'pkgtars'} = [ ( map { "$me->{'prefix'}$_"} @list ) ];

}


sub load_pkgdir {
  my ($me) = @_;

## print "LOAD: $me->{'pkgdir'}\n";

  opendir(PKGDIR, $me->{'pkgdir'});
  $me->{'pkgtars'} = [ map {$me->{'pkgdir'}."/".$_ } grep { m!\.tar\.gz! } readdir PKGDIR ];
  closedir PKGDIR;
}

sub look_for_metadata_files {
  my ($me, $dir) = @_;

  find sub { push @{$me->{'pkgs_gpt'}}, map( {$File::Find::name } grep { m!\.gpt! } $_ ) }, $dir;
}



sub load_dist_from_tar {
  my ($me) = @_;

  for my $file (@{$me->{'pkgtars'}}) {
    if ($file =~ m!\.rpm$!) {
      $me->load_rpm($file);
      next;
    }
    $me->load_gpt($file);
  }
}

sub load_dist_from_list {
  my ($me) = @_;

  my $factory = new Grid::GPT::PackageFactory;

  for my $file (@{$me->{'pkgs_gpt'}}) {

    chomp $file;
    next if( grep { /.gpt-bundle.xml/ } $file );

##print "Loading: $file\n";

    my $pkg = $factory->type_of_package($file);
    $pkg->read_metadata_file($file);
    my $node = $me->add_package(pkg => $pkg);

    next if ! defined $node;

    $node->add_gptpkgfile($file);
  }
}

sub load_gpt {
  my ($me,$file) = @_;
  chomp $file;

#    print "Loading: $file\n";
  my $tar= Archive::Tar->new();
##  $tar->read($file);

  my $ret = $tar->read($file);
  confess "ERROR: Unreadable TAR file: $file" if !defined( $ret );

  my @tarfiles=$tar->list_files();

return if grep { /packagelist|package_list/ } @tarfiles;

  my @gptfiles = grep { /pkg_data.*\.gpt/ } @tarfiles;

  my $pkgfile = scan_for_valid_pkgfile(@gptfiles);

  if (! defined $pkgfile) {
    print "WARNING: packaging data file not found in $file\n";
    return;
  }

  my $metadata=$tar->get_content($pkgfile);
  $me->{'factory'} = new Grid::GPT::PackageFactory 
    if ! defined $me->{'factory'};
  my $pkg = $me->{'factory'}->type_of_package($metadata);
  $pkg->read_metadata_file($metadata);
	$tar = undef;
          my $node = $me->add_package(
                        pkg => $pkg,
                        with_filelists => $me->{'with_filelists'},
                        context => "installtar",
                        contextData => { tar => $tar, },
                        convert => 0,
                        );
  return if ! defined $node;

  $node->add_gptpkgfile($file);
}

sub scan_for_valid_pkgfile 
{
  my (@files) = @_;

  for my $f (@files) 
  {
    if ($f =~ m!pkg_data_src!) 
    {
      return $f if $f =~ m!^(?:\./)?[^/]+/pkg_data_src!;
      return $f if $f =~ m!^(?:\./)?[^/]+/pkgdata/pkg_data_src!;
      return undef;
    }

    return $f if $f =~ m!etc/gpt/packages!;
    return $f if $f =~ m!etc/globus_packages!;
    return undef;
  }
}

sub load_rpm {
  my ($me,$file) = @_;
  chomp $file;

  my $orig = $file;

  $file =~ s!-\d+\.[^\.]+\.rpm$!!;
  my ($major, $minor) = $file =~ m!-(\d+)\.(\d+)$!;
  $file =~ s!-(\d+)\.(\d+)$!!;

  $file =~ s!.+/!!;

  my @tokens = split /_/, $file;

  my ($flavor, $pkgtype, $name, $static);

  for my $t (reverse @tokens) {

    if (! defined $static and $t eq 'static') {
      $static = $t;
      next;
    }

    if (! defined $pkgtype) {
      if ($t eq 'pgm') {
        $pkgtype = defined $static ? 'pgm_static' : 'pgm';
        next;
      }
      for my $p ('data', 'doc', 'dev', 'rtl') {
        if ($t eq $p) {
          $pkgtype = $t;
          last;
        }
      }
      die "ERROR: Package type cannot be determined from $file\n" 
        if ! defined $pkgtype;
      next;
    }

    if (! defined $flavor) {
      $flavor = $t;
      next;
    }

    $name = defined $name ? $t . "_" . $name : $t;

  }


  my $version = new Grid::GPT::V1::Version(
                                       major => $major,
                                       minor => $minor,
                                       age => 0,
                                       type => 'aging',
                                      );

  my $pkg = new Grid::GPT::V1::Package(
                                       Name => $name,
                                       Flavor => $flavor,
                                       Package_Type => $pkgtype,
                                       Version => $version,
                                      );

          my $node = $me->add_package(
                        pkg => $pkg,
                        no_package_filelist => 1,
                        );
  return if ! defined $node;

  $node->add_gptpkgfile($orig);

}

sub match_pkgfile {
  my ($me,$pkgfile) = @_;
  return $me->query(sub => sub { my $p = shift;
                                 return $p->gptpkgfile() eq $pkgfile; });
}

sub get_pkgdata_from_tar {
  my ($file) = @_;

  my $tar= Archive::Tar->new();

  my $ret = $tar->read($file); 

  if (!defined( $ret )) {
    print STDERR "ERROR: Unreadable TAR file:$file\n";
    return undef;
  }
  
  my @tarfiles=$tar->list_files();
  my @gptfiles = grep { /pkg_data.*\.gpt/ } @tarfiles;

  my $pkgfile = Grid::GPT::PkgDist::scan_for_valid_pkgfile(@gptfiles);

  if (! defined $pkgfile) {
    print STDERR "WARNING: packaging data file not found in $file\n";

    return undef;
  }

  my $metadata=$tar->get_content($pkgfile);
  my $factory = new Grid::GPT::PackageFactory;
  my $pkg = $factory->type_of_package($metadata);
  $pkg->read_metadata_file($metadata);
  return $pkg;
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
