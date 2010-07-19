package Grid::GPT::PkgMngmt::Archive;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::FilelistFunctions;
use Cwd;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';

if (defined eval { require Archive::Tar}) {
  require Archive::Tar;
} else {
  die "ERROR: Cannot find the module Archive::Tar
If it is installed in a non-standard location make sure that PERL5LIB points to the location.
You can get the module from www.cpan.org";
}

{
  my ($gtar, $gzip, $systar);
  
  sub sys_tar 
    {
      my($file, $log, @list)    = @_;
      my ($tarfile) = $file =~ m!(.+)\.gz!;
      set_tar_command();

      my $cmd = $gtar . " cf " . $tarfile . " " . (join " \\\n" , 
                                                   map { "'" . $_ . "'" }
                                                   @list);
      my $result = `$cmd`;
      $log->debug("RUNNING $cmd\n$result");

      if ($?) 
        {
          if (defined $log) 
            {
              $log->error("$tarfile could not be created:$?");
              die;
            } 
          else 
            {
              die "$tarfile could not be create:$?\n";
            }
        }

      $cmd = $gzip . " -f " . $tarfile;
      my $result = `$cmd`;
      $log->debug("RUNNING $cmd\n$result");

      if ($?) 
        {
          if (defined $log) 
            {
              $log->error("$tarfile could not be compressed:$?");
              die;
            } 
          else 
            {
              die "$tarfile could not be compressed:$?\n";
            }
        }

    }

  sub set_tar_command {
    
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
    $gzip = Grid::GPT::LocalEnv::get_tool_location('gzip');
    $gtar =  Grid::GPT::LocalEnv::get_tool_location('gtar');
    $systar =  Grid::GPT::LocalEnv::use_system_tar();
  }

  sub use_system_tar {
    set_tar_command();
    return $systar;
  }
}


# Preloaded methods go here.
sub new {
  my ($class, %arg) = @_;




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

  my $me = {
            do_rpm => $arg{'rpm'},
            verbose => $arg{'verbose'},
	    log => $arg{'log'},
            locations => $arg{'locations'},
            buildno => defined $arg{'buildno'} ? $arg{'buildno'} : 0,
            license => defined $arg{'license'} ? $arg{'license'} :
            Grid::GPT::LocalEnv::get_rpm_setting('license'),
            vendor => defined $arg{'vendor'} ? $arg{'vendor'} :
            Grid::GPT::LocalEnv::get_rpm_setting('vendor'),
            ftpsite => defined $arg{'ftpsite'} ? $arg{'ftpsite'} :
            Grid::GPT::LocalEnv::get_rpm_setting('ftpsite'),
            url => defined $arg{'url'} ? $arg{'url'} :
            Grid::GPT::LocalEnv::get_rpm_setting('url'),
            packager => defined $arg{'packager'} ? $arg{'packager'} :
            Grid::GPT::LocalEnv::get_rpm_setting('packager'),
            gpt_rpm_prefix => defined $arg{'gpt_rpm_prefix'} ? 
            $arg{'gpt_rpm_prefix'} :
            Grid::GPT::LocalEnv::get_rpm_setting('prefix'),
            target => Grid::GPT::LocalEnv::get_target(),
            rpmbuild => Grid::GPT::LocalEnv::get_tool_location('rpmbuild'),
            supress_suse_check => 
            Grid::GPT::LocalEnv::get_rpm_setting('/usr/sbin/Check') 
            eq 'Supress' ? 1 : 0,
            gptfiles => {},
            rpmfiles => {},
            skip => $arg{'skip'},
	   };


  die "ERROR: RPM building is not configured\n" if defined $me->{'do_rpm'} 
    and $me->{'rpmbuild'} eq 'Not Available';

  $me->{'gpt_rpm_prefix'} =~ s:\s+::g;
  $me->{'gpt_rpm_prefix'} =~ s:/+:/:g;
  $me->{'gpt_rpm_prefix'} =~ s:[^/]/$::g;

  if ( defined $me->{'do_rpm'} and $me->{'gpt_rpm_prefix'} !~ /^\// )
  {
    die("ERROR: Value supplied for RPM prefix is not an absolute pathname!");
  }

  $me->{'filelist_funcs'} = 
    new Grid::GPT::FilelistFunctions(log => $arg{'log'},
                                     locations => $arg{'locations'},
                                     error_out_missing => 1,
                                    );

  die "Native packages not support for this platform\n" 
    if defined $me->{'do_rpm'} and ! defined $me->{'rpmbuild'};

  bless $me, $class;

  return $me;
}


sub archive {
  my ($me, $pkgs) = @_;

  my ($dist, @rpms);

  if (defined $me->{'skip'}) {

    require Grid::GPT::PkgDist;

    $dist  = new Grid::GPT::PkgDist(pkgdir => cwd(), 
                                    all=>1,
                                    log => $me->{'log'});

    opendir PKGDIR, ".";
    @rpms = grep { m!\.rpm$! } readdir PKGDIR;
    closedir PKGDIR;
  }

  for my $p (@$pkgs) {
    my $printname = $p->label();

    if ($p->format() eq 'link') {
      if (defined $me->{'log'}) {
        $me->{'log'}->inform("SKIPPING VIRTUAL PACKAGE $printname");
      } else {
        print "SKIPPING VIRTUAL PACKAGE $printname\n";
      }
      next;
    }

    my $finds = [];
    $finds = $dist->query(
                          pkgname => $p->pkgname(),
                          flavor => $p->flavor(),
                          pkgtype => $p->pkgtype(),
                         ) if defined $dist;

    if (@$finds) {

      $me->{'gptfiles'}->{$p->label()} = $finds->[0]->gptpkgfile();

      if (! defined $me->{'do_rpm'}) {
        if (defined $me->{'log'}) {
          $me->{'log'}->inform("SKIPPING $printname ALREADY EXISTS");
        } else {
          print "SKIPPING $printname ALREADY EXISTS\n";
        }
        next;
      }

      my $rpmname = $p->pkgname() . "_" . $p->flavor() . "_" . $p->pkgtype();
      my @cand_rpms = grep { m!$rpmname! } @rpms;

      if (@cand_rpms) {
        $me->{'rpmfiles'}->{$p->label()} = $cand_rpms[0];
        next;
        if (defined $me->{'log'}) {
          $me->{'log'}->inform("SKIPPING $printname ALREADY EXISTS");
        } else {
          print "SKIPPING $printname ALREADY EXISTS\n";
        }
      }

      $me->{'current_tarfile'} = $finds->[0]->gptpkgfile(full => 1);
      $me->{'current_pkgdir'} = cwd();
      if (defined $me->{'log'}) {
        $me->{'log'}->inform_piece("CREATING RPM FOR $printname...");
      } else {
        print "CREATING RPM FOR $printname...";
      }
      my $result = $me->rpm($p);

      if ($result ) {
        if (defined $me->{'log'}) {
          $me->{'log'}->inform_piece("..DONE\n");
        } else {
          print "..DONE\n";
        }
      } else {
        if (defined $me->{'log'}) {
          $me->{'log'}->inform_piece("..NOT CREATED\n");
        } else {
          print "..NOT CREATED\n";
        }
      }
      next;
    }

    if (defined $me->{'log'}) {
      $me->{'log'}->inform_piece("CREATING PACKAGES FOR $printname...");
    } else {
      print "CREATING PACKAGES FOR $printname...";
    }

    $me->{'filelist_funcs'}->copy_flavored_pgm_files(flavor => $p->flavor(),
                                                    pkgtype => $p->pkgtype(),
                                                    filelist => $p->filelist()->getFilelistFiles(),
                                                    pkgname => $p->pkgname(),
                                                    restore => 1);

    my $result = $me->gpt_pkg($p);
    if ($result) {
      if (defined $me->{'log'}) {
        $me->{'log'}->inform_piece("..gpt");
      } else {
        print "..gpt";
      }
    }

    $result = $me->rpm($p) if defined $me->{'do_rpm'} and $result;

    if ($result and defined $me->{'do_rpm'}) {
      if (defined $me->{'log'}) {
        $me->{'log'}->inform_piece("..rpm");
      } else {
        print "..rpm";
      }
    }

    if ($result ) {
      if (defined $me->{'log'}) {
        $me->{'log'}->inform_piece("..DONE\n");
      } else {
        print "..DONE\n";
      }
    } else {
      if (defined $me->{'log'}) {
        $me->{'log'}->inform_piece("..NOT CREATED\n");
      } else {
        print "..NOT CREATED\n";
      }
    }
  }
}

sub gpt_pkg {
  my ($me, $pkg) = @_;
  my ($name, $pkgtype, $flavor, $rawfilelist, $version) = 
    ($pkg->pkgname(),
     $pkg->pkgtype(),
     $pkg->flavor(),
     $pkg->filelist()->getFilelistFiles(),
     $pkg->version_label()
    );
  my $startdir = cwd();
  chdir $me->{'locations'}->{'installdir'};

  #strip leading /

  my @filelist;

  for my $f (@$rawfilelist) {
    $f =~ s!^/+!!;
    $f =~ s!etc/globus_packages/!etc/gpt/packages/!;
    push @filelist, $f;
  }

  $me->{'filelist_funcs'}->check_missing_files(\@filelist);
  $me->{'filelist_funcs'}->archive_system_root_files(\@filelist);

  my $got_some_files = 0;

  my $archive_ext = "tar.gz";
  my $tarfile =
    "$startdir/$name-$version-$me->{'target'}-$flavor-$pkgtype.$archive_ext";
  $tarfile =
    "$startdir/$name-$version-$me->{'buildno'}-$me->{'target'}-${flavor}-$pkgtype.$archive_ext"
      if $pkgtype eq 'pgm_static';

  if (use_system_tar() and scalar(@filelist) < 200) {

    $me->{'log'}->debug("Using system tar commands");
    my $return = sys_tar($tarfile, $me->{'log'}, @filelist);
    if ($return) {
      $me->{'log'}->error("ERROR: Creating $tarfile.\n");
    } else {
      $got_some_files++;
      $me->{'log'}->inform($pkg->label() . " successfully installed.");
    }

  } else {

    $me->{'log'}->debug("BEFORE:\n" . join(" \n",@filelist));
    my $tar = Archive::Tar->new();
    my @result = $tar->add_files(@filelist);

    my @files = $tar->list_files(['name', 'prefix', 'linkname', 'size']);
    $got_some_files++ if @files;
    $me->{'log'}->debug("AFTER:\n" . join("\n",map(($_->{'prefix'} . 
                                                    "/" . $_->{'name'} . 
                                                    " "  . $_->{'linkname'} . " " . 
                                                    $_->{'size'}), @files)));

    $tar->write($tarfile,9);
  }

  my $tarname = $tarfile;
  $tarname =~ s!$startdir/!!; 
  $me->{'gptfiles'}->{$pkg->label()} = $tarname;
  $me->{'current_tarfile'} = $tarfile;
  $me->{'current_pkgdir'} = $startdir;
  chdir $startdir;
  return $got_some_files > 0;
}

sub rpm {
  my ($me, $pkg) = @_;

  my ($name, $pkgtype, $flavor, $filelist, $version) = 
    ($pkg->pkgname(),
     $pkg->pkgtype(),
     $pkg->flavor(),
     $pkg->filelist()->getFilelistFiles(),
     $pkg->version_label()
    );

  $filelist = 
    Grid::GPT::FilelistFunctions::translate_system_root_files($filelist, 
                                                              $me->{'gpt_rpm_prefix'});

  my $rawfilelist = $filelist;
  $filelist = [];
  for my $f (@$rawfilelist) {
    $f =~ s!etc/globus_packages/!etc/gpt/packages/!;
    push @$filelist, $f;
  }

  my ($binpkgname, $pkgdir) = ($me->{'current_tarfile'}, $me->{'current_pkgdir'});
  my $gpmconf = $me->{'locations'}->{'gpt_etcdir'};

  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/SOURCES");
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/BUILD");
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/RPMS");
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/SRPMS");
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/tmp");
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/rpm/SPECS");


  open(TEMPLATE, "$gpmconf/gpt_rpm.spec");
  my $specname = $binpkgname;
  $specname =~ s!\.tar(?:\.gz)?!.spec!;
  $specname =~ s!$pkgdir!$pkgdir/rpm/SPECS!;
  open(SPEC, ">$specname");

#  print "Creating specfile $specname\n";

  my $rpmstuff = ($pkg->depnode())->rpm();
  my $stupidrpmworthlessdir = "$rpmstuff->{'GPT_PACKAGE_GPT'}-$rpmstuff->{'GPT_VERSION_GPT'}";
  Grid::GPT::FilelistFunctions::mkinstalldir("$pkgdir/$stupidrpmworthlessdir");
  my $tar = Archive::Tar->new();


  my ($rootname) = $binpkgname =~ m!/([^/]+\.tar.gz)!; 
  my $result = `cp $binpkgname rpm/SOURCES/$rootname`;
  my $tarfile = "rpm/SOURCES/$ {stupidrpmworthlessdir}-rpm.tar.gz";
  $tar->add_files("$stupidrpmworthlessdir" , "rootname");
  my @files = $tar->list_files();
#  print  "AFTER:\n", @files, "\n";
  $tar->write($tarfile, 9);

  # Add shared libraries to Provides:

  my @libraries = grep { m!\.so! } @$filelist;
  my $liblist = "";
  if (@libraries) {
    for my $l (@libraries) {
      my ($lib) = $l =~ m!/([^/]+)$!;
      $liblist .= "$lib, ";
    }
    $liblist =~ s!, $! !;
#    print "liblist: $liblist\n";
    $rpmstuff->{'GPT_PROVIDES_GPT'} .= 
      defined $rpmstuff->{'GPT_PROVIDES_GPT'} ?
      ", $liblist" : $liblist;
  }

  #
  # assume our initial formatting of gpt_rpm_prefix was correct
  #

  my $gpt_rpm_prefix = $me->{'gpt_rpm_prefix'};
  $rpmstuff->{'GPT_PREFIX_GPT'} = $gpt_rpm_prefix;

  $rpmstuff->{'GPT_BIN_PKG_NAME_GPT'} = $rootname;
  $rpmstuff->{'GPT_PKG_RELEASE_GPT'} = $me->{'buildno'};
  $rpmstuff->{'GPT_FILELIST_GPT'} = join ("\n",@$filelist);
  $rpmstuff->{'GPT_LICENSE_GPT'} = $me->{'license'};
  $rpmstuff->{'GPT_VENDOR_GPT'} = $me->{'vendor'};
  $rpmstuff->{'GPT_PACKAGER_GPT'} = $me->{'packager'};
  $rpmstuff->{'GPT_URL_GPT'} = $me->{'url'};
  $rpmstuff->{'GPT_FTPSITE_GPT'} = $me->{'ftpsite'};
  for my $l (<TEMPLATE>) {
    for my $k (keys %$rpmstuff) {
#      print "$k -> |$rpmstuff->{$k}| \n";
      my $onestuff = defined $rpmstuff->{$k} ? $rpmstuff->{$k} : "";
      $l =~ s!$k!$onestuff!g;
    }
    print SPEC $l;
  }
  close TEMPLATE;
  close SPEC;
  my $rpmcmd = $me->{'rpmbuild'};
  $rpmcmd .= defined $me->{'verbose'} ? " -v" : " ";
  $rpmcmd .= " --define '_topdir $pkgdir/rpm' --define '_tmppath $pkgdir/rpm/tmp' -ba $specname";

  $rpmcmd .= " --define 'suse_check %{nil}'" if $me->{'supress_suse_check'};

  print "$rpmcmd\n" if defined $me->{'verbose'};
  $result = `$rpmcmd 2>&1`;

  print $result if defined $me->{'verbose'};
  my @lines = split /\n/, $result;

  my $finished;
  for my $l (@lines) {
#    print "|$l|\n";
    my ($file) = $l =~ m!Wrote: (.+)!;
    next if ! defined $file;
    next if $file !~ m!/RPMS/!;
    my ($basename) = $file =~ m!/([^/]+)$!;
    my $cresult = `cp $file $me->{'current_pkgdir'}/$basename`;
    $me->{'rpmfiles'}->{$pkg->label()} = "$basename";
    $finished++;
    last;
  }

  $result = `rm -rf $pkgdir/$stupidrpmworthlessdir`;
  return $finished;
}




# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::PkgMngmt:Archive - Perl extension for archiving globus binaries.

=head1 SYNOPSIS

  use Archive;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Archive was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
