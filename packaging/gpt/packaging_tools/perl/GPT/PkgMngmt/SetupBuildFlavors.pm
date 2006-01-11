package Grid::GPT::PkgMngmt::SetupBuildFlavors;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::V1::BuildFlavors;
use Grid::GPT::PkgMngmt::Build;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::GPTObject);

{
  my %environment;

  sub get_core_src {
    
    if (! defined ($environment{'core_src'})) {
      my $gpath = $ENV{GPT_LOCATION};
      
      if (!defined($gpath))
        {
          $gpath = $ENV{GLOBUS_LOCATION};
          
        }
      
      if (!defined($gpath))
        {
          die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
        }
      $environment{'core_src'} = "$gpath/etc/gpt";

      $environment{'core_src'} .= "/globus_core-src.tar.gz";

    }
    return $environment{'core_src'};
  }
}

sub new {
    my ($that, %args)  = @_;
    my $class = ref($that) || $that;

    my $me  = {
               all => $args{'all'},
               standard => $args{'std'},
               list => defined $args{'list'} ? [ @{$args{'list'}} ]: [],
               core => new Grid::GPT::V1::BuildFlavors(core => 1, 
                                                   cfg => $args{'conffile'},
                                                   std => $args{'std'},
                                                  ),
               newflavors => [],
               locations => $args{'locations'},
               log => $args{'log'},
               macros => $args{'macros'},
              };

    bless $me, $class;

    @{$me->{'list'}} = @{$me->{'core'}->{'flavors'}} 
      if defined $args{'std'} or defined $args{'all'};

    $me->scan_installed_flavors();
    $me->verify_flavor_list();

    return $me;
}

sub set_installation {
  my ($me, %args) = @_;

  $me->{'installation'} = 
    new Grid::GPT::Installation(
                                locations => $me->{'locations'},
                                log => $me->{'log'},
                               );

  $me->{'installed_core_pkgs'} = 
    $me->{'installation'}->query(pkgname => 'globus_core', pkgtype => 'dev');

}

sub scan_installed_flavors {
  my ($me) = @_;

  $me->{'installed'} = 
    new Grid::GPT::V1::BuildFlavors(installed => 1, 
                                locations => 
                                $me->{'locations'}
                               );

}

sub check_flavor {
  my ($me, $flavor) = @_;

  my @core_flavors = grep { $_ eq $flavor } @{$me->{'core'}->{'flavors'}};
  my @installed_flavors = grep { $_ eq $flavor } 
    @{$me->{'installed'}->{'flavors'}};

  return "NOT_DEFINED" if ! @core_flavors and ! @installed_flavors 
    and ! defined $me->{'macros'}->{"$ {flavor}_CONFIG_GPTMACRO"} 
      and ! defined $me->{'macros'}->{"$ {flavor}_ENV_GPTMACRO"};
  return "INSTALLED" if @installed_flavors;
  return "DEFINED";
}
sub select_core_src {
  my ($me, %args) = @_;
  my ($usercore, $coreobj) = ($args{'usercore'}, $args{'coreobj'});
  my $gptcore = get_core_src();
  my ($userversion, $objversion, $gptversion);
  if (defined $usercore) {
    my $pkg =Grid::GPT::PkgDist::get_pkgdata_from_tar($usercore);
    $userversion = $pkg->{'Version'};
  }

  if (defined $coreobj) {
    $objversion = $coreobj->{'pkg'}->{'Version'};
  }

  my $pkg=Grid::GPT::PkgDist::get_pkgdata_from_tar($gptcore);

  confess "ERROR: Cannot read the pkgdata in $gptcore\n"
    if ! defined $pkg;
  $gptversion =  $pkg->{'Version'};

  if (defined $userversion) {
    $me->{'coreobj'} = 
      new Grid::GPT::PkgMngmt::ExpandSource(tarfile => $usercore, 
                                            locations => $me->{'locations'});
    $me->{'coreversion'} = $userversion;
    return;
  }

  if (defined $objversion and $objversion->is_newer($gptversion)) {
    $me->{'coreobj'} = $coreobj;
    $me->{'coreversion'} = $objversion;
    return;
  }
    $me->{'coreobj'} = 
      new Grid::GPT::PkgMngmt::ExpandSource(tarfile => $gptcore, 
                                            locations => $me->{'locations'});
    $me->{'coreversion'} = $gptversion;
}

sub verify_flavor_list {
  my ($me, %args) = @_;
  my @bad_flavors;

  return if ! defined $me->{'list'};
  for my $f (@{$me->{'list'}}) {
    my $result = $me->check_flavor($f);
    push @bad_flavors, $f if $result eq "NOT_DEFINED";
    push @{$me->{'newflavors'}}, $f if $result eq "DEFINED";

    if ($result eq 'INSTALLED') {
      my @pkgs = grep { $f eq $_->flavor() }@{$me->{'installed_core_pkgs'}};
      push @{$me->{'newflavors'}}, $f 
        if $me->{'coreversion'}->is_newer($pkgs[0]->version()) 
          or (defined $args{'force'} and defined $args{'nosrc'});
    }
  }
  if (@bad_flavors) {
    print STDERR "ERROR: The following build flavors are not defined\n";
    for my $f(@bad_flavors) {
      print "\t$f\n";
    }
    exit 1;
  }
}

sub add_flavors {
  my ($me, $flavors) = @_;
  push @{$me->{'list'}}, @$flavors;
}

sub build_core {
  my ($me, %args) = @_;

  return if ! @{$me->{'newflavors'}};

  my ($logdir, 
      $verbose, 
      $debug, 
      $macros, 
      $static) = (
                   $args{'logdir'},
                   $args{'verbose'},
                   $args{'debug'},
                   $args{'macros'},
                   $args{'static'},
                  );

  my $logname = undef;
  $logname = $logdir . "/globus_core.log"
    if( defined($logdir) );

  my $installdir = $me->{'locations'}->{'installdir'};

  my $log = 
    new Grid::GPT::PkgMngmt::Inform(
                                    verbose => $verbose, 
                                    debug => $debug, 
                                    log => $logname,
                                    name => 'gpt-build',
                                   );
  my $filelist_funcs = 
    new Grid::GPT::FilelistFunctions(
                                     locations => $me->{'locations'}, 
                                     log=> $log
                                    );

  my $src = $me->{'coreobj'};
  my $keep_bld = -d $me->{'locations'}->{'builddir'};
  $me->{'locations'}->create_dirs(mode => 'build') 
    unless -d $me->{'locations'}->{'builddir'};
  $src->setup_source(log => $log);
  my $pkg = $src->{'pkg'};

  my $static_option = defined ($static) ? 
    {label => "static", switch => " --enable-static-only"} :
      {label => "dynamic", switch => ""};

  for my $f (@{$me->{'core'}->{'flavors'}}) {
    $me->{'core'}->{$f}->add_configure_option(%$static_option);
  }



  my $build = new Grid::GPT::PkgMngmt::Build(
                                             srcobj => $src, 
                                             name => 'globus_core', 
                                             locations => $me->{'locations'}, 
                                             verbose => $verbose, 
                                             log => $log,
                                             build_instructions =>
                                             [
                                              {command => 
                                               "MAKE_GPTMACRO distclean 2>&1; rm -f $src->{'srcdir'}/config.cache"},
                                              {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; CONFIGENV_GPTMACRO $src->{'srcdir'}/configure --with-flavor=FLAVOR_GPTMACRO CONFIGOPTS_GPTMACRO"},
                                              {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; MAKE_GPTMACRO"},
                                              {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; MAKE_GPTMACRO install"}
                                             ],
                                             macros => $macros,
                                             static => $static,
                                             installed_flavors => $me->{'core'},
                                             ignore_errors => 1,
                                             core => 1,
                                            );

    for my $f (@{$me->{'newflavors'}}) {

      my $result = $build->build($f);
      $filelist_funcs->check_installed_files(name => 'globus_core',
                                             flavor => $f,
                                             static => $static,
                                             pkg => $pkg,
                                             srcdir => $src->{'topsrcdir'});
    }

    $filelist_funcs->check_installed_files(name => 'globus_core',
                                           flavor => 'noflavor',
                                           static => $static,
                                           pkg => $pkg,
                                           srcdir => $src->{'topsrcdir'});

  $me->scan_installed_flavors();
  my (@good_flavors, @bad_flavors);
  my $message = "WARNING: The following flavors are not supported for this platform:\n";
  for my $f (@{$me->{'list'}}) {
    my $result = $me->check_flavor($f);
    if ($result eq "INSTALLED") {
      push @good_flavors, $f;
    } else {
      push @bad_flavors, $f;
      $message .= "\t$f\n";
    }
  }
  $log->error($message) if @bad_flavors;
  $me->{'locations'}->cleanbuilddir() if ! @bad_flavors and ! $keep_bld;
  $me->{'list'} = \@good_flavors;
}


sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $me = shift;
  my $type = ref($me) || croak "$me is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $me->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
  } 
  if (@_) {
    return $me->{$name} = shift;
  } else {
    return $me->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)



1;
__END__
