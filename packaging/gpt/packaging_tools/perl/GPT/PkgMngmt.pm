package Grid::GPT::PkgMngmt;

use strict;
use Carp;
use Cwd;
use Archive::Tar;
use Pod::Usage;

require Exporter;
use vars       qw($VERSION @ISA);

require Grid::GPT::Algorithms;
require Grid::GPT::FilelistFunctions;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

{
  my $rpm;
  sub get_rpm {

    return $rpm if defined $rpm;

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

    $rpm = Grid::GPT::LocalEnv::get_tool_location('rpm');

    die "ERROR: RPM installing is not available\n" if $rpm eq 'Not Available';
    return $rpm;
  }

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


sub new {
  my ($that, %args)  = @_;
  my $class = ref($that) || $that;

  my $me  = {
             locations => $args{'locations'},
             log => $args{'log'},
            };

  bless $me, $class;

  $me->{'filelist_funcs'} = 
    new Grid::GPT::FilelistFunctions(
                                     locations => $args{'locations'},
                                     log => $args{'log'},
                                    );

  return $me;
}

sub install {
  my ($me, %args) = @_;
  my ($bundles) = ($args{'bndls'});

  my @pkgs = @{$args{'pkgs'}};

  my @rpms = grep { 
    Grid::GPT::Algorithms::check_input_file
        (file => $_->gptpkgfile(full=>1))
          eq 'NATIVE_PKG' } @pkgs;

  if( @rpms )
  {
    my $ret = $me->install_pkgs(pkgs => \@rpms, format => 'native');
    return $ret if( !($ret) );
  }

  my @gpts = grep { 
    Grid::GPT::Algorithms::check_input_file
        (file => $_->gptpkgfile(full=>1))
          eq 'BIN_PKG' } @pkgs;

  if( @gpts )
  {
    my $ret = $me->install_pkgs(pkgs => \@pkgs, format => 'gpt');
    return $ret if( !($ret) );
  }

  $me->install_bundles($bundles) if @$bundles;

  $me->refresh_cache();

  return 1;
}

sub remove {
  my ($me, %args) = @_;
  my ($pkgs, $bundles) = ($args{'pkgs'}, $args{'bndls'});

  $me->remove_pkgs(pkgs => $pkgs);

  $me->remove_bundles($bundles);
  $me->refresh_cache();
}

sub install_pkgs {
  my ($me, %args) = @_;

  my ($pkgs, $format) = ($args{'pkgs'}, $args{'format'});

  $me->_install_rpms($pkgs) if $format eq 'native';

  if ($format ne 'native') 
  {
    for my $p(@$pkgs) 
    {
      my $ret = $me->_install_gpt_pkg($p);
      return $ret if( !($ret) );
    }
  }

  for my $p(@$pkgs) 
  {
    pkg_format_file(pkgdir => $me->{'locations'}->{'pkgdir'},
                    pkg    => $p,
                    format => $format, mode => 'WRITE');
  }

  return 1;
}

sub remove_pkgs {
  my ($me, %args) = @_;

  my ($pkgs) = ($args{'pkgs'});

  my @natives = grep {$_->format() eq 'native'} @$pkgs;
  my @gpts = grep {$_->format() eq 'gpt'} @$pkgs;

  $me->_remove_rpms(\@natives) if @natives;

  for my $p (@gpts) {
    $me->_remove_gpt_pkg($p);
  }

  for my $p (@$pkgs) {

    $me->_remove_setup($p);

    pkg_format_file(pkgdir => $me->{'locations'}->{'pkgdir'},
                    pkg => $p,
                    mode => 'REMOVE');
  }

}

sub install_bundles {
  my ($me, $bundles) = @_;

if( ! -w $me->{'locations'}->{'installdir'} )
{
  print "Can't write to $me->{'locations'}->{'installdir'}\n";
}

if( ! -r $me->{'locations'}->{'installdir'} )
{
  print "Can't read from $me->{'locations'}->{'installdir'}\n";
}

  for $b (@$bundles) {
    $b->save_bundle_def($me->{'locations'}->{'installdir'});

    $me->{'log'}->inform("Bundle " . $b->label() . 
                         " successfully installed.",1);
  }
}


sub remove_bundles {
  my ($me, $bundles) = @_;
  for $b (@$bundles) {
    if (-f $b->{'BundleDefFile'}) {
      my $result = system("rm -f $b->{'BundleDefFile'}"); 
       $me->{'log'}->inform("Bundle " . $b->label() . " removed.",1);
    }
  }
}

sub _install_gpt_pkg {
  my ($me, $pkg) = @_;

  my $result;


  my $startdir = cwd();

  my @tarfiles;

  if( ! -w $me->{'locations'}->{'installdir'} )
    {
      print "Can't write to $me->{'locations'}->{'installdir'}\n";
    }
  
  if( ! -r $me->{'locations'}->{'installdir'} )
    {
      print "Can't read from $me->{'locations'}->{'installdir'}\n";
    }

  chdir $me->{'locations'}->{'installdir'};

  if (use_system_tar()) {
    $me->{'log'}->debug("Using system tar commands");
    @tarfiles  = sys_untar($pkg->gptpkgfile(full =>1), $me->{'log'});
    if (! @tarfiles) {
      $me->{'log'}->error("ERROR: Problem installing " . 
                          $pkg->gptpkgfile(full =>1) . 
                          ".\n Empty file list.");
    }

    $me->{'log'}->inform($pkg->label() . " successfully installed.");
    $result++;
  } else {
    my $tar = Archive::Tar->new();

    my $ret = $tar->read($pkg->gptpkgfile(full =>1));

    if( !defined( $ret ) )
      {
        my $msg = "ERROR: [PkgMngmt->_install_gpt_pkg] " .
          "Unreadable TAR file: " .
            $pkg->gptpkgfile(full =>1);
        $me->{'log'}->error( $msg );

        return 0; 
      }

    #  my @tarfiles = $tar->list_files(['name', 'prefix', 'linkname', 'size']);
    #  print  "FILES:\n", join("\n",map(($_->{'prefix'} . "/" . $_->{'name'} . 
    #                                    " "  . $_->{'linkname'} . " " . 
    #                                    $_->{'size'}), @tarfiles)), "\n";
    @tarfiles = $tar->list_files();

    my $msg = "Installing files: \n\t" . join "\n\t", @tarfiles;
    $me->{'log'}->debug($msg);


    if (! @tarfiles) {
      $me->{'log'}->error("ERROR: Problem installing " . 
                          $pkg->gptpkgfile(full =>1) . 
                          ".\n Empty file list.");
    }

    my $retval= $tar->extract(@tarfiles);
    if (!($retval)){
      my $msg =  $tar->error();
      $msg .=  $retval . "is the return from extract_archive\n";
      $msg .= "did not successfully install" . $pkg->gptpkgfile(full =>1) . "\n";
      $msg .= "$me->{'locations'}->{'installdir'}\n";
      $me->{'log'}->error($msg);
      $result = 0;
    }else {
      $me->{'log'}->inform($pkg->label() . " successfully installed.");
      $result++;
    }

  }


  my ($login,$pass,$uid,$gid) = getpwuid($<)
    or die "$< not in passwd file";

  if ($login eq 'root') {
    chown $<, $(, @tarfiles;
  }

  chdir $startdir;

  $me->{'filelist_funcs'}->install_system_root_files(\@tarfiles);

  return $result;
}

sub _install_rpms {
  my ($me, $pkgs) = @_;


  my $rpmcmd = get_rpm();

  my $forceflag = defined $me->{'force'} ? '--force' : '';
  my $vvflag = defined $me->{'verbose'} ? '-v' : '';
  my $rpmprefix  = "--prefix $me->{'locations'}->{'installdir'}";

  my $fileline = "";
  for my $p (@$pkgs) {
    my $f = $p->gptpkgfile(full =>1);
    $fileline .= "\\\n  $f";
  }


  $me->{'log'}->inform("Executing: $rpmcmd -i $forceflag $vvflag  $rpmprefix $fileline\n");

  my $result;

  $result = system("$rpmcmd -i $forceflag $vvflag  $rpmprefix $fileline"); 
  return $result;
}

sub _remove_gpt_pkg
{
  my ($me, $p) = @_;
  my $retval = 0;
  my $installdir = $me->{'locations'}->{'installdir'};
  my $filelist = $p->{'filelist'}->getFilelistFiles();
  $filelist = 
    Grid::GPT::FilelistFunctions::translate_system_root_files($filelist, 
                                                              $installdir);
  for my $f(@$filelist) 
    {
      if (-f "$f" or -l "$f") {
        my $result = system("rm -f $f");
        $me->{'log'}->error("WARNING problems removing file $f\n") 
          if $result;
        $retval += $result;
      } else {
        $me->{'log'}->inform("Skipping $f because it doesn't exist.\n") 
      }
    }
  $me->{'log'}->inform($p->label() . " successfully removed.") 
    if ! $retval;

}

sub pkg_format_file
{
  my (%args) = @_;

  my ($mode, $format, $pkg) = ($args{'mode'}, $args{'format'}, $args{'pkg'});
  my ($pkgname, $flavor, $pkgtype) = 
    (
     defined $args{'pkgname'} ? $args{'pkgname'} : $pkg->pkgname(), 
     defined $args{'flavor'} ? $args{'flavor'} : $pkg->flavor(), 
     defined $args{'pkgtype'} ? $args{'pkgtype'} : $pkg->pkgtype(), 
    );

  my $pkgdir = $args{'pkgdir'};

  my $file = "$pkgdir/" . $pkgname ."/"
    . $flavor . $pkgtype . ".format";

  if ($mode eq "WRITE") {
    open FILE, ">$file";
    print FILE "$format\n";
    close FILE;
    return undef;
  }

  if ($mode eq "READ") {
    return undef if ! -f $file;
    open FILE, $file;
    my $format = <FILE>;
    close FILE;
    chomp $format;
    return $format;
  }

  if ($mode eq "REMOVE") {
    return undef if ! -f $file;
    system ("rm -f $file");
    return undef;
  }

  return undef;
}

sub _remove_setup
{
  my ($me, $p) = @_;
  my $setupdir = "$me->{locations}->{'setupdir'}"; 
  return if ! defined $p->setupname();
  my $d = $p->setupname();
  my $f = $p->pkgname();
  if (-f "$setupdir/$d/$f.gpt") {
    my $result = system("rm -f $setupdir/$d/$f.gpt");
    $me->{'log'}->error("WARNING problems removing file setupdir/$d/$f.gpt\n") 
      if $result;
  }
}

sub _remove_rpms
{
  my ($me, $pkgs) = @_;
  my $forceflag = defined $me->{'force'} ? '--force' : '';
  my $vvflag = defined $me->{'verbose'} ? '-v' : '';
  my $fileline = "";
  for my $p (@$pkgs) {
    my $f = $p->pkgname() . "_" . $p->flavor() . "_" . $p->pkgtype();

    my $query = `rpm -q $f 2>&1`;

    #print "$f -- $query\n";
    next if $query =~ m!not\s+installed!;

      $fileline .= "\\\n $f";
    }
  my $rpmcmd = get_rpm();
  $me->{'log'}->inform("Executing: $rpmcmd -e $forceflag $vvflag $fileline\n");
  my $result = system("$rpmcmd -e $forceflag $vvflag $fileline");

  if ($result) {
    $me->{'log'}->error("ERROR: rpm cannot remove the packages $fileline\n");
    exit 1;
  }

  return;
}

sub refresh_cache {
   my ($me) = @_;
   return if ! defined eval "require Grid::GPT::InstallationCache";

   require Grid::GPT::InstallationCache;

   Grid::GPT::InstallationCache::refresh(locations => $me->{'locations'});

}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
