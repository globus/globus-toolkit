package Grid::GPT::Locations;


use strict;
use Carp;
use Cwd;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter);

require Grid::GPT::FilelistFunctions; 

sub new
{
  my ($that, %args)  = @_;
  my $class = ref($that) || $that;

  my $me  = {
             tmpdir => $args{'tmpdir'},
             builddir => $args{'builddir'},
             bindir => $args{'bindir'},
             srcdir => $args{'srcdir'},
             installdir => $args{'installdir'},
             gpt_etcdir => undef,
             gpt_amdir => undef,
             gpt_aclocaldir => undef,
             pkgdir => undef,
             altpkgdir => undef,
             bundledir => undef,
             setupdir => undef,
            };
  
  bless $me, $class;
  $me->_init();
  return $me;
}

sub _init {
  my ($me) =@_;

  $me->_init_installdirs();
  $me->_init_builddir();
  $me->_init_tmpdir();
  $me->_init_gptdir();

  for my $d ('tmpdir',
             'builddir',
             'bindir',
             'srcdir',
             'installdir',
             'pkgdir',
             'bundledir',
             'setupdir') {

    next if ! defined $me->{$d};
    $me->{$d} = Grid::GPT::FilelistFunctions::abspath($me->{$d});
  }
}

sub _init_gptdir {
  my ($me) =@_;
  my $gptdir = $ENV{'GPT_LOCATION'};
  $me->{'gpt_etcdir'} = "$gptdir/etc/gpt";
  $me->{'gpt_amdir'} = "$gptdir/share/gpt/amdir";
  $me->{'gpt_aclocaldir'} = "$gptdir/share/gpt/aclocal";
}

sub _init_tmpdir {
  my ($me) =@_;
  my $tmpdir= defined $me->{'tmpdir'} ? $me->{'tmpdir'} : "/tmp";

  my $time=time();
  my $tmpd=$tmpdir."/"."gpt-"."$$"."-".$time;
  $tmpdir=$tmpd;

  $me->{'tmpdir'} = $tmpd;
}

sub create_dirs {
  my ($me, %args) = @_;

  if ($args{'mode'} eq 'install' ) {
    Grid::GPT::FilelistFunctions::mkinstalldir($me->{'bundledir'});
    Grid::GPT::FilelistFunctions::mkinstalldir($me->{'setupdir'});
    my $startdir = cwd();
    chdir "$me->{'installdir'}/etc";
    my $result = `ln -s gpt/packages globus_packages` 
      if ! -d "globus_packages";
    return
  }
  if ($args{'mode'} eq 'build' ) {
    Grid::GPT::FilelistFunctions::mkinstalldir($me->{'builddir'});
    return
  }
  if ($args{'mode'} eq 'bundle' ) {
    Grid::GPT::FilelistFunctions::mkinstalldir($me->{'bindir'});
    return
  }
  if ($args{'mode'} eq 'tmp' ) {
    Grid::GPT::FilelistFunctions::mkinstalldir($me->{'tmpdir'});
    my $result = `chmod 700 $me->{'tmpdir'}`;
    return
  }

}

sub _init_builddir {
  my ($me) =@_;

  $me->{'builddir'} = defined $me->{'builddir'} ? $me->{'builddir'} : "./BUILD";
  $me->{'bindir'} = defined $me->{'bindir'} ? $me->{'bindir'} : "./bundle_pkgs";
  $me->{'srcdir'} = defined $me->{'srcdir'} ? $me->{'srcdir'} : "./source";
}

sub _init_installdirs {
  my ($me) =@_;

  my $gpath = $ENV{GPT_INSTALL_LOCATION} ? $ENV{GPT_INSTALL_LOCATION} 
    : $ENV{GLOBUS_LOCATION};


  $me->{'installdir'} = defined $me->{'installdir'} ? 
    $me->{'installdir'} : $gpath;

  die "ERROR: GPT_INSTALL_LOCATION needs to be set before running this script.
Or use the -location switch"
    if ! defined $me->{'installdir'};

  # Determine what kind of package directory we have

  my ($altpkgdir, $pkgdir) = ("etc/globus_packages", "etc/gpt/packages");

  if (-d "$me->{'installdir'}/etc/globus_packages" and 
      ! -d "$me->{'installdir'}/etc/gpt/packages") {
    $pkgdir = "etc/globus_packages";
    $altpkgdir = "etc/gpt/packages";
  }

  $me->{'bundledir'} = "$me->{'installdir'}/etc/gpt/bundles";
  $me->{'pkgdir'} = "$me->{'installdir'}/$pkgdir";
  $me->{'altpkgdir'} = "$me->{'installdir'}/$altpkgdir";
  $me->{'setupdir'} = "$me->{'installdir'}/$pkgdir/setup";
}

sub cleanbuilddir {
  my ($me) = @_;

  return system("rm -rf $me->{'builddir'}");
}

sub cleantmp() {
  my ($me) = @_;

  my $top = $me->{'tmpdir'};
  opendir(DIR, $top);
  my @contents = readdir DIR;
  closedir DIR;


  my @dirs = grep { -d "$top/$_" and ! m!^\.! } @contents;
  my @files = grep { ! -d $_ } map { "$top/$_" } @contents;

  for my $f (@files) {
    unlink($f) or warn "WARNING: couldn't unlink $f: $!";
  }

  for my $d (@dirs) {
    cleandir("$top/$d");
  }

  rmdir $top;
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
