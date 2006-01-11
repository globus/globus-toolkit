package Grid::GPT::FilelistFunctions;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::PkgMngmt::Inform;
use Grid::GPT::PkgMngmt::ExpandSource;
require Grid::GPT::PkgMngmt;
use Cwd;
use Config;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';
{
  my $startdir = cwd();

  sub startdir { return $startdir; }
}
# Preloaded methods go here.
sub new {
  my ($class, %args) = @_;
  my $me = {
            locations => $args{'locations'},
            log => $args{'log'},
            error_out_missing => $args{'error_out_missing'},
	   };

  bless $me, $class;

  return $me;
}


sub check_installed_files {
  my ($me, %args) = @_;
  my ($name, 
      $flavor, 
      $static,
      $copy_pgm_files,
      $srcdir, 
      $pkg, 
      $force,
      $noflavors) = ($args{'name'}, 
                    defined $args{'noflavors'} ? 'noflavor' : $args{'flavor'}, 
                    $args{'static'}, 
                    $args{'copy_pgm_files'},
                    $args{'srcdir'}, 
                    $args{'pkg'}, 
		    $args{'force'},
                    $args{'noflavors'});

  my $installdir = $me->{'locations'}->{'installdir'};

  my $master_filelist = $me->get_master_filelist( srcdir=> $srcdir);

  # presence of a master filelist means non native GPT packages
  # ergo need to generate filelists and iunstall packaging data files.

  if (defined $master_filelist) {

    $master_filelist = $me->flavor_filelist(filelist => $master_filelist, 
                                            flavor => $flavor,
                                           pkg => $pkg)
      if ! defined $noflavors && $flavor ne 'noflavor';

      $me->generate_pkgdata(flavor => $flavor, 
                            noflavors => $noflavors, 
                            static => $static,
                            pkg => $pkg,
                            master_filelist => $master_filelist,
                            srcdir => $srcdir);
    }

  #check for the existance of packaging data files
  for my $pkgtype (@Grid::GPT::V1::Definitions::package_types) {
    my $pkgdatadir = "$me->{'locations'}->{'pkgdir'}/$name";
    my $altpkgdatadir = "$me->{'locations'}->{'altpkgdir'}/$name";
    my ($filelistname, $pkgdataname) = 
      ("$ {flavor}_$ {pkgtype}.filelist",
       "pkg_data_$ {flavor}_$ {pkgtype}.gpt");


    # testing if pkgdata files exist

    $filelistname = "$pkgdatadir/$filelistname" 
      if -f "$pkgdatadir/$filelistname";

    $filelistname = "$altpkgdatadir/$filelistname" 
      if -f "$altpkgdatadir/$filelistname";

    $pkgdataname = "$pkgdatadir/$pkgdataname" 
      if -f "$pkgdatadir/$pkgdataname";

    $pkgdataname = "$altpkgdatadir/$pkgdataname" 
      if -f "$altpkgdatadir/$pkgdataname";

    my $list = $me->get_installed_filelist(name => $name, 
                                           flavor => $flavor, 
                                           pkgtype => $pkgtype);

    my $pkgdatasubdir = $pkgdatadir;
    $pkgdatasubdir =~ s!$installdir/!!;

    my $altpkgdatasubdir = $altpkgdatadir;
    $altpkgdatasubdir =~ s!$installdir/!!;


    my @notpkgdata;
    @notpkgdata = grep { ! m!$pkgdatasubdir!} 
      grep { ! m!$altpkgdatasubdir!} @$list if defined $list;

    #remove empty packages
    if (! @notpkgdata ) {
      if ( -f $filelistname or -f $pkgdataname) {
        $me->{'log'}->announce("REMOVING empty package $name-$flavor-$pkgtype");
        my $result;
        $result = system("rm $filelistname") if -f $filelistname;
        $result = system("rm $pkgdataname") if -f $pkgdataname;
      }
      next;
    }

    #remove bad pgm package
    if (defined $static and $pkgtype eq 'pgm') {
      if ( -f $filelistname or -f $pkgdataname) {
        $me->{'log'}->announce("REMOVING empty package $name-$flavor-$pkgtype");
        my $result;
        $result = system("rm $filelistname") if -f $filelistname;
        $result = system("rm $pkgdataname") if -f $pkgdataname;
      }
      next;
    }

    #remove bad pgm_static package
    if (! defined $static and $pkgtype eq 'pgm_static') {
      if ( -f $filelistname or -f $pkgdataname) {
        $me->{'log'}->announce("REMOVING empty package $name-$flavor-$pkgtype");
        my $result;
        $result = system("rm $filelistname") if -f $filelistname;
        $result = system("rm $pkgdataname") if -f $pkgdataname;
      }
      next;
    }
    
    $me->check_missing_files($list);

    $me->copy_flavored_pgm_files(flavor => $flavor,
                                 pkgname => $name,
                                 force => $force,
                                 pkgtype => $pkgtype,
                                 filelist => $list) if defined $copy_pgm_files;

    Grid::GPT::PkgMngmt::pkg_format_file(
                                         mode => 'WRITE', 
                                         pkgname => $name, 
                                         flavor => $flavor, 
                                         format => 'gpt', 
                                         pkgtype => $pkgtype,
                                         pkgdir => 
                                         $me->{'locations'}->{'pkgdir'},
                                        );
  }


}

sub check_missing_files {

  my ($me, $list) = @_;
  # Error about missing files
  my $missing = 0;
  my $installdir = $me->{'locations'}->{'installdir'};
  my $xlist = translate_system_root_files($list, $installdir);

  for my $f (@$xlist) {
    if (! -f "$f") {
      $me->{'log'}->inform("WARNING: \"$f\" not found",1) if ! -f "$installdir/$f";
      $missing++ if defined $me->{'error_out_missing'};
      
    }
  }
  
  if (defined $me->{'error_out_missing'} and $missing) {
    $me->{'log'}->error("ERROR: Cannot continue. Files are missing");
    exit 1;
  }

}

sub contains_system_root_files {
  my ($list) = @_;

  return (grep { m!SYSTEM_ROOT! } @$list) > 0;
}


sub translate_system_root_files {
  my ($list, $installdir) = @_;

  my @newlist;
  for my $f (@$list) {
    my $file = $f;
    if ($file =~ s!SYSTEM_ROOT!!) {
      push @newlist, $file;
    } else {
      push @newlist, "$installdir/$file";
    }
  }
  return \@newlist;
}

sub archive_system_root_files {
  my ($me,$list) = @_;
  my $installdir = $me->{'locations'}->{'installdir'};

  for my $f (@$list) {
    next if $f !~ m!SYSTEM_ROOT!;
    my $sysloc = $f;
    $sysloc =~ s!SYSTEM_ROOT!!;

    my $path = "$installdir/$f";
    $path =~ s!^(.+/)[^/]*$!$1!;
    mkinstalldir($path);
    $me->{'log'}->debug("copying $sysloc to $installdir/$f");
    my $result = system("cp -p $sysloc $installdir/$f");
  }
}

sub install_system_root_files {
  my ($me,$list) = @_;

  my $installdir = $me->{'locations'}->{'installdir'};

  for my $f (@$list) {
    next if $f !~ m!SYSTEM_ROOT!;
    my $sysloc = $f;
    $sysloc =~ s!SYSTEM_ROOT!!;

    my ($path) = $sysloc =~ m!^(.+/)[^/]*$!;
    mkinstalldir($path);
    $me->{'log'}->debug("copying $installdir/$f to $sysloc");
    my $result = system("cp -p $installdir/$f $sysloc");
  }
}


sub flavor_install {
  my ($me, %args) = @_;
  my ($srcdir, $flavor, $pkg) = ($args{'srcdir'}, 
                                 $args{'flavor'}, 
                                 $args{'pkg'});
  my %sofiles;

  my $installdir = $me->{'locations'}->{'installdir'};
  my $filelist = $me->get_master_filelist(srcdir => $srcdir);

  return $filelist if ! defined $filelist;

  if (defined $pkg) {
    return $filelist if $pkg->{'ColocateLibraries'} eq "no";
  }


  for my $f (@$filelist) {
    my $name = $f;
    
    # Assume all headers are flavored
    if ($f =~ m!/?include/!) {
      my $dir = $f;
      $dir =~ s!/[^/]+\.h!!;
      $dir =~ s!^/?include!include/$flavor!;
      mkinstalldir("$installdir/$dir");
      $name =~ s!^/?include/!include/$flavor/!;
      my $result = `mv $installdir/$f $installdir/$name` 
        if -f "$installdir/$f";
    }
    if ($f =~ m!lib/lib.+\.a!) {
      next if $f =~ m!$flavor\.a!;
      my $newf = $f;
      $newf=~ s!(.+)\.a!$ {1}_$flavor\.a!;
      my $result = `mv $installdir/$f $installdir/$newf`
        if -f "$installdir/$f";
    }
  }
}

sub flavor_filelist {
  my ($me, %args) = @_;

  my ($filelist, $flavor, $pkg) = ($args{'filelist'},
                                   $args{'flavor'},
                                   $args{'pkg'});

  my @flavored_filelist;
  my %sofiles;
  my %sonames;

  my $missing = 0;

  return $filelist if ! defined $filelist;

  my $installdir = $me->{'locations'}->{'installdir'};

  if (defined $pkg) {
    return $filelist if $pkg->{'ColocateLibraries'} eq "no";
  }

  for my $f (@$filelist) {
    my $name = $f;

    # Append the flavor to each library file.
    if ($f =~ m!lib/!)
      {
        $name =~ s!(lib[^.]+)\.!$ {1}_$flavor.!;
        
        if ($name =~ m!\.(?:s[ol]|dylib)\.?!) {


          my ($dir, $libname) = $name =~ m!(.+)/([^/]+)$!;
          my $soname = $libname;
          $soname =~ s!(\.(?:s[ol]|dylib)).*!!;

          next if defined $sonames{$soname};

          $me->{'log'}->debug("SONAME found: $soname");

          if (! defined $sofiles{$dir}) {
            opendir(LIBS,"$installdir/$dir");
            $sofiles{$dir} = [ grep { m!\.(?:s[ol]|dylib)! } readdir LIBS ];
            closedir LIBS;
           $me->{'log'}->debug("SONAME files found: " . join ("\n\t" ,@{$sofiles{$dir}}));
         }
          $me->{'log'}->announce("WARNING $f not found",1) if ! @{$sofiles{$dir}};

          $missing++ if defined $me->{'error_out_missing'};

            my @flavored_libs;
          push @flavored_libs, map { "$dir/$_" } grep { m!$soname\.! } 
            @{$sofiles{$dir}};

           $me->{'log'}->debug("SONAME flavored libs found: " . join ("\n\t" ,@flavored_libs));

          $sonames{$soname}++;

          my $msg = "The following libraries were added for soname $soname:\n";
          for my $f(@flavored_libs) {
            $msg .= "\t$f\n";
          }

          $me->{'log'}->inform("$msg");

          push @flavored_filelist, @flavored_libs;
          next;
        }

        # all other lib files
        push @flavored_filelist, $name;
        next;
      }
 
    # Assume all headers are flavored
   if ($f =~ m!/?include/!) {

      $name =~ s!^/?include/!include/$flavor/!;
      push @flavored_filelist, $name;
      next;
    }

    # Pass thru all other files
    push @flavored_filelist, $name;
  }

  if (defined $me->{'error_out_missing'} and $missing) {
    $me->{'log'}->error("ERROR: Cannot continue. Files are missing");
    exit 1;
  }

  return \@flavored_filelist;
}


sub generate_pkgdata {
  my ($me, %args) = @_;

  my ($flavor, 
      $noflavors, 
      $static, 
      $master_filelist, 
      $pkg, 
      $srcdir) = (
                  $args{'flavor'},
                  $args{'noflavors'},
                  $args{'static'},
                  $args{'master_filelist'},
                  $args{'pkg'},
                  $args{'srcdir'});

  my $sort;
  my $filessort;
  my $mangling = 1;

  if (defined $pkg->ColocateLibraries()) {
    $mangling = $pkg->ColocateLibraries() ne 'no' ? 1 : undef;
  }

  if (-f "$srcdir/MyFilelists.pm") {
    # Found a package specific file sorting module

    # Add srcdir to package search path
    push @INC, $srcdir;

    require MyFilelists;
    $sort = new MyFilelists(list => $master_filelist, flavor => $flavor,
                           mangling => $mangling);

  } else {

    # Use default p-n-b file sorting functions
    require Grid::GPT::FilelistSort;
    $filessort = new Grid::GPT::FilelistSort(flavor =>$flavor,
                                         list => $master_filelist,
                                         noexpand => 1,
                                         log => $me->{'log'}
                                        );
  }

  # set up a hash of filesorting functions for each pkgtype
  my %funcs = (data=> defined $sort ? 
               sub{ $sort->data_files()} : sub{_data_files($filessort)}, 
               dev=> defined $sort ? 
               sub{ $sort->dev_files()} : sub{_dev_files($filessort, $mangling)}, 
               doc=> defined $sort ? 
               sub{ $sort->doc_files()} : sub{_doc_files($filessort)}, 
               pgm=> defined $sort ? 
               sub{ $sort->pgm_files()} : sub{_pgm_files($filessort)}, 
               pgm_static=> defined $sort ? 
               sub{ $sort->pgm_static_files()} : 
               sub{_pgm_static_files($filessort)}, 
               rtl=>  defined $sort ? 
               sub{ $sort->rtl_files()} : sub{_rtl_files($filessort, $mangling)}, 
              );

#  for my $f(@$master_filelist) {
#    print "$f\n"
#  }
  

    for my $pkgtype (@Grid::GPT::V1::Definitions::package_types) {
      # Weed out invalid package types first.
      next if $pkgtype ne "pgm" and 
        $pkgtype ne "pgm_static" and
          $pkgtype ne "rtl" and 
            $pkgtype ne "dev";

      # Weed out the static conditions next;

      next if defined $static and $pkgtype eq 'pgm';
      next if ! defined $static and $pkgtype eq 'pgm_static';

      # Take care of the noflavor condition
      # Need this because there is no way to determine if executables are flavored.
      if ($flavor eq 'noflavor' and ! defined $noflavors)
        {
          next if $pkgtype eq 'pgm' or 
            $pkgtype eq 'pgm_static' or 
              $pkgtype eq  'rtl';
        }


      $me->install_pkgdata(pkg => $pkg, 
                           flavor => $flavor, 
                           pkgtype => $pkgtype, 
                           filelist => &{$funcs{$pkgtype}}());
    }

}

sub get_installed_filelist {
  my ($me, %args) = @_;
  my ($name, $flavor, $pkgtype) = ($args{'name'}, $args{'flavor'}, $args{'pkgtype'});
  my $pkgdatadir = "$me->{'locations'}->{'pkgdir'}/$name";
  my ($filelistname, $pkgdataname) = 
    ("$pkgdatadir/$ {flavor}_$ {pkgtype}.filelist",
     "$pkgdatadir/pkg_data_$ {flavor}_$ {pkgtype}.gpt");

  return undef if ! -f $filelistname;

  open (LIST, $filelistname);
  my @List = <LIST>;
  close LIST;

  chomp @List; # remove carriage returns

  my @trimmed;

  for my $l (@List) {
    push @trimmed, $l if ! grep {$_ eq $l } @trimmed;
  }

  return \@trimmed;
}

sub get_master_filelist {
  my ($me, %args) =@_;
  my($srcdir) = ($args{'srcdir'});
  my $filelist_name = "$srcdir/filelist";

  return undef if ! -f $filelist_name;
      
  open (FILELIST, $filelist_name) or 
    die "ERROR could not open $filelist_name\n";
  my @filelist = <FILELIST>;
  close FILELIST;
  for (@filelist) {
    s!^/+!!;
    chomp;
  }

  return \@filelist;
}

sub install_pkgdata {
  my ($me, %args) = @_;
  my ($pkg, $flavor, $pkgtype, $filelist) =
    ($args{'pkg'},
     $args{'flavor'},
     $args{'pkgtype'},
     $args{'filelist'});

  my $name = $pkg->Name();

  return if ! defined $filelist;

  my $pkgdatadir = "$me->{'locations'}->{'pkgdir'}/$name";
  my $installdir = $me->{'locations'}->{'installdir'};

  mkinstalldir($pkgdatadir);

  my $pkgdatasubdir = $pkgdatadir;
  $pkgdatasubdir =~ s!$installdir/!!;

  my ($filelistname, $pkgdataname) = 
    ("$pkgdatasubdir/$ {flavor}_$ {pkgtype}.filelist",
     "$pkgdatasubdir/pkg_data_$ {flavor}_$ {pkgtype}.gpt");



  my $bin_pkg = $pkg->convert_metadata($pkgtype, $flavor);
  $bin_pkg->output_metadata_file("$installdir/$pkgdataname");

  push @$filelist, ($filelistname, $pkgdataname);
  open (FILELIST, ">$installdir/$filelistname") 
    or die "ERROR: could not open $installdir/$filelistname\n";
  for (@$filelist) {
    print FILELIST "$_\n";
  }
  close FILELIST;

}


sub backup_pkgdata {
  my ($me, %args) = @_;
  my ($pkg, $flavor) =
    ($args{'pkg'},
     $args{'flavor'},
    );

  return if $flavor eq 'noflavor';

  my $name = $pkg->Name();

  my $pkgdatadir = "$me->{'locations'}->{'pkgdir'}/$name";
  
  return if ! -d $pkgdatadir;

  my $backupdir = "$pkgdatadir/bak";

  opendir PKG, $pkgdatadir;
  my @files = grep { m!(?:$flavor)_! } readdir PKG;

  closedir PKG;

  return if ! @files;

  my ($filelistnames, $pkgdatanames) = 
    ("$ {flavor}_\*.filelist","pkg_data_$ {flavor}_\*.gpt");

  mkinstalldir("$backupdir");
  $me->{'log'}->inform("Creating backups for \\\n" . join( "\\\n", @files));

  my $result = system("cp -f $pkgdatadir/$filelistnames $pkgdatadir/$pkgdatanames $backupdir");

}



sub restore_pkgdata {
  my ($me, %args) = @_;
  my ($pkg, $flavor) =
    ($args{'pkg'},
     $args{'flavor'},
    );

  return if $flavor eq 'noflavor';

  my $name = $pkg->Name();

  my $pkgdatadir = "$me->{'locations'}->{'pkgdir'}/$name";
  my $backupdir = "$pkgdatadir/bak";
  
  return if ! -d $backupdir;

  opendir (PKG, $pkgdatadir);

  my @pkgdata = grep { m!$flavor! } grep { m!\.filelist! or 
                         m!\.gpt! } readdir PKG;

  closedir PKG;

  opendir (BAK, $backupdir);

  my @backups = grep { m!$flavor! } grep { m!\.filelist! or 
                         m!\.gpt! } readdir BAK;

  closedir BAK;


  for my $f (@backups) {
    next if grep { $f eq $_ } @pkgdata;
    $me->{'log'}->inform("Restoring file $f");
    my $result = system("cp $backupdir/$f $pkgdatadir");
  }

}


sub copy_flavored_pgm_files {
  my ($me, %args) = @_;
  my ($flavor, 
      $pkgtype, 
      $filelist, 
      $restore, 
      $force,
      $pkgname) = (
                   $args{'flavor'}, 
                   $args{'pkgtype'}, 
                   $args{'filelist'},
                   $args{'restore'},
                   $args{'force'},
                   $args{'pkgname'},
                  );

  return if $pkgtype ne 'pgm' and 
    $pkgtype ne 'pgm_static' or 
      $flavor eq 'noflavor';


  my $installdir = $me->{'locations'}->{'installdir'};
  my $binname = $pkgtype eq 'pgm_static' ? 'static' : 'shared';

  for my $f (@$filelist) {
    my ($dir, $name) = $f =~ m!(.+)/([^/]+)$!;

    next if $dir =~  m!/etc/\w+packages!;

    $dir = "$installdir/$dir";

    next if -l "$dir/$flavor/$binname/$name";

    next if -f "$dir/$flavor/$binname/$name" and 
      ! defined $restore and 
        ! defined $force;

    my ($source, $dest) = ("$installdir/$f", "$dir/$flavor/$binname/$name");

    ($source, $dest) = ("$dir/$flavor/$binname/$name", "$installdir/$f")
      if defined $restore;

    if (! -f $source) {
       $me->{'log'}
         ->inform("WARNING: FilelistFunction \"$source\" does not exist\n") 
           # Hack to suppress warning when restoring files.
           # Need some way to determine that backups are supposed to exist.
           if ! defined $restore;
      next;
    }

    $me->{'log'}
      ->inform("COPYING file $source for package $pkgname-$flavor/$binname-$pkgtype");
    mkinstalldir("$dir/$flavor/$binname");
    my $result = system("cp -f $source $dest");
    my $rawmode = (stat($source))[2]; 
    my $mode = sprintf "%04o",$rawmode & 07777;
    $result = system("chmod $mode $dest");
  }
}

sub abspath {
  my ($file) = @_;
  my $home = $ENV{'HOME'};
  $file =~ s!~!$home!;
  my $startd = startdir();
  $file =~ s!^\./!$startd/!;
  $file = "$startd/$file" if $file !~ m!^\s*/!;
  return $file;
}

sub mkinstalldir {
  my $dir = abspath(shift);
  my @dirlist = split m!/!, $dir;
  my $subdir= "";
  for my $d (@dirlist) {
    next if $d eq "";
    $subdir .= "/$d";
    if (! -d $subdir) {
      my $result = system("mkdir -p $subdir");
      die "ERROR: system mkdir $subdir failed: $?" if $result != 0;
    }
  }
}

sub _pgm_files {
  my $filessort = shift;
  $filessort->noflavor_files();
  $filessort->add_package_metadata_files('pgm');
  my $list = $filessort->get_list();
  $filessort->reset();
  return $list;
}

sub _pgm_static_files {
  my $filessort = shift;
  $filessort->noflavor_files();
  $filessort->add_package_metadata_files('pgm_static'); 
  my $list = $filessort->get_list();
  $filessort->reset();
  return $list;
}

sub _rtl_files {
  my ($filessort, $mangling) = @_;
  my $result = [];
  $filessort->flavored_files() if defined $mangling;
  $filessort->extract_dynamic_libs();
  $filessort->add_package_metadata_files('rtl');
  my $list = $filessort->get_list();
  push @$result, @$list;
  $filessort->reset();
  $filessort->flavored_files() if defined $mangling;
  $filessort->extract_libtool_libs();
  $list = $filessort->get_list();
  push @$result, @$list;
#  for my $f(@$result) {
#    print "rtl: $f\n"
#  }
  $filessort->reset();
  return $result;
}

sub _dev_files {
  my ($filessort, $mangling) = @_;
  my $result = [];
  $filessort->flavored_files() if defined $mangling;
  $filessort->extract_static_libs();
  my $list = $filessort->get_list();
  push @$result, @$list;
  $filessort->reset();
  $filessort->flavored_headers() if defined $mangling;
  $filessort->noflavor_headers() if ! defined $mangling;
  $filessort->add_package_metadata_files('dev');
  $list = $filessort->get_list();
  push @$result, @$list;
  $filessort->reset();
  return $result;
}

sub _data_files {
  return [];
}

sub _doc_files {
  return [];
}

# Autolod methods go after =cut, and are processed by the autosplit program.

1;

__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::FilelistFunctions - Perl extension for building globus binaries.

=head1 SYNOPSIS

  use Build;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Build was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
