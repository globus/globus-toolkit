package Grid::GPT::PkgMngmt::Build;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::PkgMngmt::Inform;
use Grid::GPT::PkgMngmt::BuildMacros;
use Cwd;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';

# Preloaded methods go here.
sub new {
  my ($class, %arg) = @_;
  my $me = {
	    srcobj => $arg{'srcobj'},
            build_instructions => $arg{'build_instructions'} || 
            [
             {command => "MAKE_GPTMACRO distclean"},
             {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; CONFIGENV_GPTMACRO $arg{'srcobj'}->{'srcdir'}/configure CONFIGOPTS_GPTMACRO --with-flavor=FLAVOR_GPTMACRO STATIC_FLAG_GPTMACRO"},
             {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; MAKE_GPTMACRO"},
             {command => "GLOBUS_LOCATION=INSTALLDIR_GPTMACRO; export GLOBUS_LOCATION; MAKE_GPTMACRO install"}
            ],
            ignore_errors => $arg{'ignore_errors'},
            locations => $arg{'locations'},
            log => $arg{'log'},
            name => $arg{'name'},
            core => $arg{'core'},
	   };

  bless $me, $class;

  my $macros = $arg{'macros'};
  if (! defined($arg{'build_instructions'})) {

    $me->{'using default build instructions'}++;

  }
  # Add the install directory to the filelist
  if (defined ($me->{'srcobj'}->{'filelist'})) {
    $me->{'filelist'} = [];
    for my $f (@{$me->{'srcobj'}->{'filelist'}}) {
      chomp $f;
      push @{$me->{'filelist'}}, $f;
    }
  }
  $me->{'macros'} = 
    new Grid::GPT::PkgMngmt::BuildMacros(
                                         srcobj => $arg{'srcobj'},
                                         locations => $arg{'locations'},
                                         user_macros => $macros,
                                         log => $me->{'log'},
                                         filelist => $me->{'filelist'},
                                         static => $arg{'static'},
                                         installed_flavors =>
                                         $arg{'installed_flavors'},
                                         flavor_choices =>
                                         $arg{'flavor_choices'},
                                         core => $arg{'core'},
                                        );

  return $me;
}

sub build {
  my ($me, $flavor) = @_;
  my $returning = 1;

  my $startdir = cwd();

  $me->{'log'}->announce("Changing to $me->{'srcobj'}->{'srcdir'}");
  chdir $me->{'srcobj'}->{'srcdir'};

  if (defined $flavor) {
    $me->{'log'}->announce("BUILDING FLAVOR $flavor",1);
  } else {
      $me->{'log'}->announce("BUILDING $me->{'name'}",1);
  }

  for my $bs (@{$me->{'build_instructions'}}) {

    my $build_step = $me->{'macros'}->expand($bs,$flavor);

    next if ! defined $build_step;

    # Perform the step
    my $result = $me->{'log'}->action($build_step);

    if ($result and $build_step !~ m!patch|clean!) { 
      if (defined $me->{'ignore_errors'}) {
        $me->{'log'}->announce("...SKIPPING $flavor",1);
        $returning = undef;
        last;
      } else {
      #results are bad print them out.
      die "ERROR: Build has failed\n";
      }
    }
  }

  chdir $startdir;
  $me->{'log'}->announce("Changing to $startdir");
  # Check for filelist.
  $me->{'filelist'} = $me->{'macros'}->{'flavored_filelist'};
  return $returning;
}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;

__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::PkgMngmt:Build - Perl extension for building globus binaries.

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
