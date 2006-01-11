package Grid::GPT::PkgMngmt::BuildMacros;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::PkgMngmt::Inform;
use Grid::GPT::PkgMngmt::ExpandSource;
use Grid::GPT::PkgMngmt::FlavorMacros;
use Grid::GPT::FilelistFunctions;
use Cwd;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';

# Preloaded methods go here.
sub find_make {
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

  return Grid::GPT::LocalEnv::get_tool_location('gmake');
}


sub new {
  my ($class, %arg) = @_;
  my $me = {
            user_macros => $arg{'user_macros'},
            macros => {},
            log => $arg{'log'},
            installed_flavors =>
            $arg{'installed_flavors'},
            flavor_choices =>
            $arg{'flavor_choices'},
            locations => $arg{'locations'},
            flavor_macros => 
            new Grid::GPT::PkgMngmt::FlavorMacros( 
                                                  flavors => 
                                                  $arg{'installed_flavors'},
                                                  user_macros => 
                                                  $arg{'user_macros'},
                                                  log => $arg{'log'},
                                                 ),
            core => $arg{'core'},
	   };

  bless $me, $class;

  $me->add_macro('BUILDDIR_GPTMACRO', $arg{'srcobj'}->{'srcdir'});
  $me->add_macro('GLOBUSDIR_GPTMACRO', $arg{'locations'}->{'installdir'}); 
  $me->add_macro('INSTALLDIR_GPTMACRO', $arg{'locations'}->{'installdir'}); 

  
#  $me->{'ENV_GPTMACRO'} = "LDFLAGS='-L$arg{'locations'}->{'installdir'}/lib';";

  $me->add_macro('STATIC_LINK_GPTMACRO', 
                 defined $arg{'static'} ? "yes" : "no");

  $me->add_macro('STATIC_FLAG_GPTMACRO', 
                 defined $arg{'static'} ? "--enable-static-only" : "");

  $me->{'filelist_funcs'} = 
    new Grid::GPT::FilelistFunctions(log => $arg{'log'},
                                     locations => $arg{'locations'},
                                    );


  $me->add_macro('MAKE_GPTMACRO', find_make());


  #setup the run macros
  $me->add_macro('RUN_FLAVOR_INSTALL_GPTMACRO', sub {
    $me->{'flavored_filelist'} = 
      $me->{'filelist_funcs'}->flavor_install(srcdir => $arg{'srcobj'}->{'topsrcdir'},
                                              flavor => $_[0],
                                             );
  });

  $me->add_macro('RUN_FLAVOR_MAKEFILES_GPTMACRO', sub {
    $me->flavor_makefiles(@_);
  });

  while (my ($m, $value) = each %{$arg{'user_macros'}}) {
    $me->add_macro($m, $value);
  }

  return $me;
}

sub expand {
  my ($me, $buildstep, $flavor) = @_;
  my $command = $buildstep->{'command'};
  $me->{'log'}->debug("Command before expansion: $command\n");
  if ($command =~ m!(RUN_\w+_GPTMACRO)!s) {
    my $runsub = $1;
    if (defined($me->{'macros'}->{$runsub})) {
      $me->{'log'}->inform("Running: $command");
      &{$me->{'macros'}->{$runsub}}($flavor, $buildstep->{'args'});
      return undef;
    }
  }

  # set the flavor macro
  $me->replace_macro('FLAVOR_GPTMACRO',$flavor);

  # Set flavor macros

  my $flavoredmacros = $me->{'flavor_macros'}->macros(flavor => $flavor,
                                                   core => $me->{'core'});
  if (defined $flavoredmacros) {
    while (my ($m, $value) = each %$flavoredmacros) {
      $me->add_macro($m,$value);
    }
  }

  # substitute in flavored config options
  $me->setup_flavor_macros($flavor);

  $me->{'log'}->debug("MACRO LIST:\n" . $me->dump());

  # Substitute in the macro values.
  for my $m (sort sort_macro keys %{$me->{'macros'}}) {
    next if $m !~ m!GPTMACRO!;
    my $mvalue = $me->{'macros'}->{$m};
    next if ! defined $mvalue;
    $command =~ s!$m!$mvalue!g;
  }
    
  # Remove undefined macros
  while ($command =~ s!(\w+_GPTMACRO)!!g) {
    $me->{'log'}->inform("WARNING: $1 is empty\n");
  }

  $me->{'log'}->debug("Command after expansion: $command\n");

  return $command;
}

sub add_macro {
  my ($me, $macro, $value) = @_;

  my $log = $me->{'log'};
  return if ! defined $macro;
  $log->debug("Adding macro $macro=" . 
              (defined $value ? $value : "UNDEFINED"));
  $log->inform("WARNING: Overriding macro $macro. 
         $me->{'macros'}->{$macro} is now $value\n") 
    if defined $me->{'macros'}->{$macro};
  $me->{'macros'}->{$macro} = $value;
}

sub replace_macro {
  my ($me, $macro, $value) = @_;

  return if ! defined $value;

  if (defined $me->{'macros'}->{$macro}) {
    return if $value eq $me->{'macros'}->{$macro};
  }

  my $log = $me->{'log'};
  $log->debug("Replacing macro $macro=" . 
              (defined $me->{'macros'}->{$macro} ? 
              $me->{'macros'}->{$macro} : "undef") . 
              " with $value");
  $me->{'macros'}->{$macro} = $value;
}

sub sort_macro {

#  print "comparing '$a' to '$b'\n";
  return -1 if length($a) > length($b);
  return 1 if length($a) < length($b);
  return $a cmp $b;
}


sub setup_flavor_macros {
  my ($me, $flavor) = @_;
  my $macrolist = $me->{'flavor_macros'}->macrolist();
  #remove $flavor from the macro name so that it resembles what is in the build
  #step
  for my $m (@$macrolist) {
    next if ! defined $me->{'macros'}->{"$ {flavor}_$m"};
    $me->replace_macro($m, $me->{'macros'}->{"$ {flavor}_$m"});
  }

  my ($configopts, $configenv);
  if ($me->{'core'}) {
    $configopts = $me->{'macros'}->{'CORE_CONFIG_GPTMACRO'};
    $configenv = $me->{'macros'}->{'CORE_ENV_GPTMACRO'};
  } else {
    $configopts = defined $me->{'user_macros'}->{'CONFIGOPTS_GPTMACRO'} ? 
      $me->{'user_macros'}->{'CONFIGOPTS_GPTMACRO'}: "";
    $configenv = ( defined $me->{'user_macros'}->{'CONFIGENV_GPTMACRO'} ? 
                   $me->{'user_macros'}->{'CONFIGENV_GPTMACRO'} : "") . " " . 
                   $me->{'macros'}->{'CORE_ENV_GPTMACRO'};
  }
  $me->replace_macro('CONFIGOPTS_GPTMACRO', $configopts);
  $me->replace_macro('CONFIGENV_GPTMACRO', $configenv);

}

sub dump {
  my ($me) = @_;
  my $result = "";
  for my $m (sort sort_macro keys %{$me->{'macros'}}) {
    $result .= "/macro=$m/value=" .
      (defined $me->{'macros'}->{$m} ? $me->{'macros'}->{$m} : "UNDEF") . 
       "\n";
  }
  return $result;
}

sub flavor_makefiles {
  my ($me, $flavor, $arglist) = @_;
  my $makesub = sub {$me->flavor_a_makefile(shift, $flavor, $arglist)};
  scan_for_makefiles($me->{'macros'}->{'BUILDDIR_GPTMACRO'}, $makesub);
}

sub scan_for_makefiles {
  my ($dir, $sub) = @_;
  opendir(DIR, $dir);
  my @dirlist = readdir(DIR);
  close DIR;
  for my $f(@dirlist) {
    next if $f =~ m!^\.+!;
    &{$sub}("$dir/$f") if -f "$dir/$f";
    scan_for_makefiles("$dir/$f", $sub);
  }
}

sub flavor_a_makefile {
  my ($me, $file, $flavor, $arglist) = @_;

  return if $file !~ m![Mm]akefile(?:\.in)?! and 
    $file !~ m!configure! and
        $file !~ m!\.(?:mk|mak)! and # for openldap *.mk files
          $file !~ m!shlib/!; # openssl shared libarary creation script.

  return if $file =~ m!\.gpm_orig!;

  my (@libs, @regexes, $apos);
  while ($arglist =~ m!(\w+)\s*=\s*\'([^\']+)\'!g) {
    my ($name, $args, $apos) = ($1, $2, pos());
    if ($name eq 'libs') {
      my @mylibs = split m!\s+!, $args;
      push @libs,@mylibs;
    }
    if ($name eq "regex") {
      $args =~ m!(.*)FLAVOR(.*)!;
      push @regexes, {pre => $1, post => $2};
    }
    pos $apos;
  }


  my $bakfile = "$file.gpm_orig";

  my $result;

  if (! -f $bakfile) {
    $result = `mv $file $bakfile`;
    $me->{'log'}->debug("Creating $bakfile");
  }


  local (*OLDFILE, *NEWFILE);
  open (OLDFILE, $bakfile) || die "Could not open $bakfile\n";
  open (NEWFILE, ">$file") || die "Could not open $file\n";

  $me->{'log'}->inform("Modifying $file");

  my $line;
  while ($line = <OLDFILE>) {
    my $newline = $line;

    for my $l (@libs) {
      $newline =~ s!-l$l(\W)!-l$ {l}_$flavor$1!g;
      $newline =~ s!lib$l([\$\.])!lib$ {l}_$flavor$1!g;
      $newline =~ s!lib$l(_la)!lib$ {l}_$ {flavor}$1!g;
    }
    for my $r (@regexes) {
#      print "|$newline| $r->{'pre'} $r->{'post'}\n" if $file =~ m!Makefile.org!;
      $newline =~ 
        s!\Q$r->{'pre'}$r->{'post'}\E!$r->{'pre'}_$flavor$r->{'post'}!g;
#      print "after:$newline" if $file =~ m!Makefile.org!;
    }
    print NEWFILE $newline
  }

  close NEWFILE;
  close OLDFILE;

  $result = `chmod 755 $file` if $file =~ m!configure!;

}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;

__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::PkgMngmt:BuildMacros - Perl extension for managing globus-build macros..

=head1 SYNOPSIS

  use BuildMacros;
  $me->{'macros'} = new Grid::GPT::PkgMngmt::BuildMacros(srcobj => $arg{'srcobj'},
                                               globusdir => $arg{'globusdir'},
                                               flavors => $arg{'flavors'},
                                               macros => $macros,
                                               log => $me->{'log'},
                           static => $arg{'static'},
                                               installed_flavors =>
                                               $arg{'installed_flavors'},
                                               flavor_choices =>
                                               $arg{'flavor_choices'},
                                              );


  for my $bs (@build_instructions) {

    my $build_step = $me->{'macros'}->expand($bs,$flavor);

    next if ! defined $build_step;
   }

=head1 DESCRIPTION

b<Grid::GPT::PkgMngmt::BuildMacros> is used to manage build macros and expand
them inside a build instruction.


=head1 MACRO TYPES

b<Grid::GPT::PkgMngmt::BuildMacros> manages three different types of macros.

The first type is a simple expansion macro.  Which gets expanded with
the same value every time the macro is encountered.  BUILDDIR_GPTMACRO
is an example of this.

The second type are flavored macros. The value of these macros are
changed depending on the build flavor label.  An example of this is

=head1 MACROS

=over 4

=item CONFIGOPTS_GPTMACRO

This macro contains configuration options that are always invoked
regardless of the build flavor.

=item BUILDDIR_GPTMACRO

This macro contains the absolute path to the top level directory of
the source being built.

=item PATCHDIR_GPTMACRO

This macro contains the absolute path to the directory containing
patches for a source package.

=item GLOBUSDIR_GPTMACRO

This macro points to the directory containing all of the installed
files need to build a source package.  It also is the installation
location for the source package.  During the build process it contains
the same value as the environmental variable $GLOBUS_LOCATION.

=item CONFIGENV_GPTMACRO

This macro contains the environmental variables that are set before
running configure.  These variables are a combination of both flavored
and non-flavored variables.  The flavored variables are contained in
the macro flavor_ENV_GPTMACRO.  The non-flavored variables are
contained in the macro ENV_GPTMACRO.

  $me->{'ENV_GPTMACRO'} = "CPPFLAGS='-I$arg{'globusdir'}/include -I$arg{'globusdir'}/include/FLAVOR_GPTMACRO'; LDFLAGS='-L$arg{'globusdir'}/lib';";

  $me->{'STATIC_LINK_GPTMACRO'} = defined $arg{'static'} ? "yes" : "no";

  $me->{'INSTALLDIR_GPTMACRO'} = $me->{'GLOBUSDIR_GPTMACRO'};

  $me->{'MAKE_GPTMACRO'} = find_make();

  $me->{'RUN_FLAVOR_INSTALL_GPTMACRO'} = sub {
    $me->{'flavored_filelist'} = 
      $me->{'filelist_funcs'}->flavor_install(@_);
  };
  $me->{'RUN_FLAVOR_MAKEFILES_GPTMACRO'} = sub {

=back



=head1 METHODS

=over 4

=item new





=back

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
