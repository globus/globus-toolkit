package Grid::GPT::PkgMngmt::ExpandSource; 
use strict; 
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require Grid::GPT::PkgMngmt::Archive;
require Archive::Tar;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::FilelistFunctions;
use Grid::GPT::PackageFactory;
use Grid::GPT::PkgDist;
use Grid::GPT::PkgMngmt::Inform;
use Cwd;
use File::Find;
use Carp;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT            = qw();
$VERSION           = '0.01';

# Preloaded methods go here.
{
  my ($gtar, $gunzip, $systar);

  sub sys_untar 
    {
      my($file, $log)    = @_;
      set_untar_command();

      my $cmd = $gunzip . " < $file | " . $gtar . " xvf -";

      my @list           = `$cmd 2>&1`;
      if ($?) 
    {
      if (defined $log) 
        {
          $log->error("$file could not be untarred:$?");
          die;
        } 
      else 
        {
          die "$file could not be untarred:$?\n";
        }
    }

      for (@list) 
        {
          s!^(?:x\s+)?(?:\./)?!!;
          s!,.+$!!;
          chomp;
        }

      return @list;
}

  sub set_untar_command {

    return if defined $gtar;

    my $gpath = $ENV{GPT_LOCATION};

    if (!defined($gpath))
      {
        $gpath = $ENV{GLOBUS_LOCATION};
      }

    if (!defined($gpath))
      {
        die "GPT_LOCATION or needs to be set before running this script";
      }

    # Add path to LocalEnv module to @INC
    push @INC,"$gpath/var/lib/perl";

    die "ERROR: GPT is not configured. Use gpt-config\n" 
      if ! defined eval ("require Grid::GPT::LocalEnv;");

    require Grid::GPT::LocalEnv;
    $gunzip = Grid::GPT::LocalEnv::get_tool_location('gunzip');
    $gtar =  Grid::GPT::LocalEnv::get_tool_location('gtar');
    $systar =  Grid::GPT::LocalEnv::use_system_tar();
  }
  sub use_system_tar {
    set_untar_command();
    return $systar;
  }
}


sub open_bundle 
{
  require Grid::GPT::Algorithms;
  my (%arg)        = @_;
  my @sources;
  my $builddir     = $arg{'locations'}->{'builddir'};

  my $file       = Grid::GPT::FilelistFunctions::abspath($arg{'file'});

  my $filetype = Grid::GPT::Algorithms::check_input_file(file => $file);

  if( $filetype eq 'SRC_BUNDLE' or $filetype eq 'SRC_2xBUNDLE' )
  {
    my $srcbundle = new Grid::GPT::PkgMngmt::ExpandSource(tarfile => $file,
                                                    locations => 
                                                    $arg{'locations'},
                                                    log => $arg{'log'},
                                                   );
    my @list       = $srcbundle->untar();
    my @pl         = grep {m!packaging_list!} @list;

    my @pkglist;
    for my $l (@list) {
      my $file = "$builddir/$l";
      my $filetype = 
        Grid::GPT::Algorithms::check_input_file(file => $file);
      push @pkglist, $file if $filetype eq 'SRC_PKG'; 
    }

    my $dist = new Grid::GPT::PkgDist(
                                      locations => $arg{'locations'},
                                      pkgtars => \@pkglist,
                                     );

    open(PL, "$builddir/$pl[0]") ||
      die "ERROR: $pl[0] could not be accessed for bundle $arg{'file'}\n";

    for my $l (<PL>) 
    {
      next if $l !~ m!\w!;
      chomp $l;

      my $node = $dist->query(pkgname => $l);

      if (! @$node) 
      {
        print "ERROR: Archive not found for package $l\nArchive:\n";
        for my $p (@{$dist->{'pkgs'}}) 
        {
          print "\t",$_->gptpkgfile(),"\n";
        }
        exit 1;
      }

      my $src = 
        new Grid::GPT::PkgMngmt::ExpandSource(
                                              tarfile => 
                                              $node->[0]->gptpkgfile(full=>1),
                                              locations => $arg{'locations'});
      push @sources, $src;
    }
    close PL;
    return \@sources;
  }

  if ($filetype eq 'SRC_PKG') 
    {
      my $src = new Grid::GPT::PkgMngmt::ExpandSource(tarfile => $arg{'file'}, 
                                                      locations => $arg{'locations'});
      return undef if ! defined $src;

      $sources[0] = $src;
      return \@sources;
  }

  if( $filetype eq 'FILE_DOES_NOT_EXIST' )
  {
    `ls $file`;
    print "\n";
    return undef;
  }

  if ($filetype ne 'UNKNOWN')
    {
      print STDERR "ERROR: $arg{'file'} is a binary bundle or package.  Use gpt-install\n";
      return undef;
    }
  
    print STDERR "ERROR: $arg{'file'} is not a GPT source package or bundle\n";
    return undef;

}

sub new {
  my ($class, %arg) = @_;
  # set the following directories
  # source directory.
  
  my $me = { srcdir    => $arg{'srcdir'},
             topsrcdir => $arg{'srcdir'},
             srcfile   => $arg{'srcfile'},
             locations  => $arg{'locations'},
             log  => $arg{'log'},
             tarfile   => $arg{'tarfile'} };
  $|++; # need for timely print outputs
  
  for my $f ('topsrcdir','srcdir','tarfile','srcfile') 
  {
    next if ! defined $me->{$f};

    $me->{$f} = Grid::GPT::FilelistFunctions::abspath($me->{$f});
    
    if (! defined -f $me->{$f}) {
      print STDERR "ERROR: $me->{$f} is not a valid path\n";
      return undef;
    }
  }
  
  bless $me, $class;
  
  return $me;
}

sub setup_source {
  my ($me, %args)        = @_;
  my $log = $me->{'log'} = $args{'log'};
   my $startdir          = cwd();

  $me->{'srcdir'}        = $startdir if ! defined $me->{'srcdir'};

  $me->expand() if defined $me->{'tarfile'};
  $me->{'topsrcdir'}     = $me->{'srcdir'} if ! defined $me->{'topsrcdir'};

  my $result             = opendir(DIR, $me->{'srcdir'});
  if (! $result) {
    $log->error("ERROR can't access $me->{'srcdir'}\n");
    return 1;
  }
  my @contents           = readdir(DIR);

  if (! defined $me->{'srcfile'}) 
  {
    my $pkgdata          = findindir( qr/^pkgdata$/, 
                                      "pkgdata directory",
                                      \@contents, 
                                      $log );

    if (defined ($pkgdata)) 
    {
      $me->{'srcfile'}   = "$me->{'srcdir'}/pkgdata/pkg_data_src.gpt.in";
      if (! -f $me->{'srcfile'}) 
      {
        $log->error("ERROR: Source pkgdata file not found in " . 
                    "$me->{'srcdir'}/." . 
                    "  Are you sure this is a source package?");
        return 1;
      }
    } 
    else 
    {
      $me->{'srcfile'}   = "$me->{'srcdir'}/pkg_data_src.gpt";
      if (! -f $me->{'srcfile'}) 
      {
        $log->error("ERROR: Source pkgdata file not found in " . 
                    "$me->{'srcdir'}/." . 
                    "  Are you sure this is a source package?");
        return 1;
      }
    }
  }


  # extract pkg metadata
  my $factory = new Grid::GPT::PackageFactory;
  $log->inform("Scanning $me->{'srcfile'}");
  $me->{'pkg'} = $factory->type_of_package($me->{'srcfile'});
  if (! defined $me->{'pkg'}) {
    $log->error("ERROR: $me->{'srcfile'} is not a package data file");
    return 1;
  }
  $me->{'pkg'}->{'disable_version_checking'} = $args{'disable_version_checking'};
  $me->{'pkg'}->read_metadata_file($me->{'srcfile'});

  if (defined $me->{'pkg'}->{'SrcDir'}) {
    $me->{'srcdir'} = "$me->{'srcdir'}/$me->{'pkg'}->{'SrcDir'}";
    return 0;
  }

  if (! -f "$me->{'srcdir'}/Makefile.in" and ! -f "$me->{'srcdir'}/INSTALL") 
  {
    my @subdirs = 
      grep { -f "$me->{'srcdir'}/$_/Makefile.in" or 
             -f "$me->{'srcdir'}/$_/INSTALL" }
        grep { -d "$me->{'srcdir'}/$_" } 
          @contents;

      if (@subdirs > 1) 
      {
        $log->error("ERROR: Found multiple sources in " .
                    "$me->{'srcdir'}/[ @subdirs ]");
        return 1;
      }

    $me->{'srcdir'} .= "/$subdirs[0]" if @subdirs;
  }

  return 0;
}

sub findindir
{
  my ($expression, $lookfor, $contents, $log) = @_;
  my @hits = grep {m!$expression!} @$contents;

  if (@hits > 1 ) 
  {
    $log->error("ERROR: Too many $lookfor found");
    die;
  }

  return $hits[0] if @hits;
  return undef;
};


sub expand 
{
  my ($me)        = @_;
  
  return if !defined $me->{'tarfile'};
  
  # need to untar a source tarball
  
  $me->{'log'}->inform("UNPACKING $me->{'tarfile'}");

  my @list        = $me->untar();

  die "ERROR: Untar failed\n" if ! @list;

  my $srcdir      = $list[0];
  $srcdir         =~ s!(^[^/]+)/.+!$1!;

  $me->{'srcdir'} = "$me->{'locations'}->{'builddir'}/$srcdir";

}

sub untar {
  my($me)    = @_;

  my $file = $me->{'tarfile'};

  my $startdir = cwd();

  my @tarfiles;

  if (use_system_tar()) {
    $me->{'log'}->debug("Using system tar commands");
    chdir $me->{'locations'}->{'builddir'};
    @tarfiles  = sys_untar($file, $me->{'log'});
    return @tarfiles;
  }

  require Archive::Tar;

  my $tar = Archive::Tar->new();

  my $ret = $tar->read($file);

  if( !defined( $ret ) )
    {
      my $msg = "ERROR: [PkgMngmt->_install_gpt_pkg] " .
        "Unreadable TAR file: " .
          $file;
      $me->{'log'}->error( $msg );
      return 0; 
    }

  @tarfiles = $tar->list_files();



  if (! @tarfiles) {
    $me->{'log'}->error("ERROR: Problem installing " . 
                        $file . 
                        ".\n Empty file list.");
  }

  if( ! -w $me->{'locations'}->{'builddir'} )
    {
      print "Can't write to $me->{'locations'}->{'builddir'}\n";
    }
  
  if( ! -r $me->{'locations'}->{'builddir'} )
    {
      print "Can't read from $me->{'locations'}->{'builddir'}\n";
    }
      
  chdir $me->{'locations'}->{'builddir'};
  my $retval= $tar->extract(@tarfiles);
  if (!($retval)){
    my $msg =  $tar->error();
    $msg .=  $retval . "is the return from extract_archive\n";
    $msg .= "did not successfully install" . $file . "\n";
    $msg .= "$me->{'locations'}->{'builddir'}\n";
    $me->{'log'}->error($msg);
    @tarfiles = ();
  }

  chdir $startdir;
  my @files;
  for my $f (@tarfiles) {
    $f =~ s!^\.?/?!!;
    push @files, $f;
  }
  my $msg = "Unpacked files: \n\t" . join "\n\t", @files;
  $me->{'log'}->debug($msg);

  return @files;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::PkgMngmt:ExpandSource - Perl extension for expanding source packages
and bundles.

=head1 SYNOPSIS

  use ExpandSource;
  my $src = new Grid::GPT::PkgMngmt::ExpandSource(srcdir => $s,
                                        srcfile => $srcfile,
                                       );
  my @sources = Grid::GPT::PkgMngmt::ExpandSource::open_bundle(file => "$startdir/$t", 
                                                     builddir => $tmpdir);

 for my $o (@sources) {
   $o->setup();
 }

=head1 DESCRIPTION

B<Grid::GPT::PkgMngmt::ExpandSource> is used to unarchive a source package or bundle and prepare the contents for building.


=head1 METHODS

=over 4

=item open_bundle(file => "$startdir/$t", builddir => $tmpdir)

This is a class function that untars a source bundle and returns a
list of ExpandSource objects.  Each object represents a source
package.  A bundle is an archive of source packages with a file called
I<packaging_list> which lists the packages in build dependent order.
For example here is the contents of the globus_gsi_bundle.tar.gz:

   -rw-r--r-- mbletzin/mbletzin 152868 2001-09-25 10:59:03 ./gsi/globus_core-2.0.tar.gz
   -rw-r--r-- mbletzin/mbletzin 8557949 2001-09-25 10:50:02 ./gsi/globus_openssl-0.9.6b.tar.gz
   -rw-r--r-- mbletzin/mbletzin  120013 2001-09-25 10:59:04 ./gsi/globus_core_setup-2.0.tar.gz
   -rw-r--r-- mbletzin/mbletzin  248338 2001-09-25 10:59:06 ./gsi/globus_ssl_utils-2.0.tar.gz
   -rw-r--r-- mbletzin/mbletzin  161845 2001-09-25 10:59:09 ./gsi/globus_gssapi_gsi-2.0.tar.gz
   -rw-r--r-- mbletzin/mbletzin  120526 2001-09-25 10:59:10 ./gsi/globus_gss_assist-2.0.tar.gz
   -rw-r--r-- mbletzin/mbletzin      52 2001-09-25 10:59:10 ./gsi/packaging_list

The contents of the packaging_list file is:

   core
   core_setup
   openssl
   ssl_utils
   gssapi_gsi
   gss_assist

=item setup_source

This object function expands the source tarball if necessary and sets
the attributes that describe the build directory.


=back

=head1 ATTRIBUTES

=over 4

=item srcdir

Points to the top of the source directory

=item srcfile

Points to the location of the source package metadata.

=item builddir

Directory in which the sources are expanded.

=item tarfile

Name of the source package to be expanded.

=item globusdir

Location where the globus packaging tools are installed.

=item build_instructions

Contents of the build_instructions file.  Currently this is not being
used.

=item filelist

Contents of the filelist file.  The file is needed for those packages
which don't generate filelists as part of their build process.

=back

=head1 AUTHOR

Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) globus-build(1).

=cut
