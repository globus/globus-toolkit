package DistGPT;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA);

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

{
  my %masks = (
               core => "globus_core",
               gpt => "packaging_tools",
            );

my @buildorder = (
             "core",
             "gpt",
            );


  sub get_key_list {
    return \@buildorder;
  }

  sub get_mask {
    my $mask = shift;
    return $masks{$mask};
  }

}

sub new {
  my ($that, %args)  = @_;

  my $class = ref($that) || $that;
  my $me  = {
             gtar_location => $args{'gtar'},
             gunzip_location => $args{'gunzip'},
             buildlist => $args{'building'},
             tars => {},
             srcdirs => {},
             topdir => $args{'topdir'},
            };
  bless $me, $class;

  $me->init_tarfiles($args{'tarconf'}) if defined $args{'tarconf'};

  push @INC, "$me->{'topdir'}/packaging_tools/perl/GPT";

  require Localize;

  my $localize = new Grid::GPT::Localize(
                              gunzip => $args{'gunzip'}, 
                              gtar => $args{'gtar'},
                              systar => 1
                             );

  $localize->probe_for_tools();

  $me->{'gtar_location'} = $localize->{'gtar_location'};
  $me->{'gunzip_location'} = $localize->{'gunzip_location'};

  return $me;

}

sub find_perl {
  my (%args) = @_;
  my ($perl_location, $perl_version, $topdir) = 
    ($args{'perl_location'}, $args{'perl_version'}, $args{'topdir'});

  push @INC, "$topdir/packaging_tools/perl/GPT";

  require Localize;

  return Grid::GPT::Localize::find_perl($perl_location, $perl_version);
}


sub get_tarfile {
  my ($me, $name) = @_;
  return $me->{'tars'}->{$name};
}


sub init_tarfiles {
  my ($me, $file) = @_;

  if (! -f $file) {
    print STDERR "WARNING: $file does not exist use -tarconf flag to specify tar file locations\n";
    return;
  }
  open LOC, $file;
  for my $l (<LOC>) {
    next if $l =~ m!^\s*\#!;
    my ($name, $tar) = $l =~ m!^\s*([^=\s]+)\s*=\s*\"([^\"]+)\"!;
    $tar =~ s!GPT_TOPDIR!$me->{'topdir'}!;
    $me->{'tars'}->{$name} = $tar;
  }
}

sub match_srcdirs {
  my ($me, $needautotools) = @_;

  my $supportdir = "$me->{'topdir'}/support";

  opendir SUPPORT, $supportdir;

  my @dirs = grep { m!\w! } readdir SUPPORT;

  closedir SUPPORT;

  for my $k (@{ $me->get_keys() } ) {

    if ($k eq 'gpt') {
      $me->{'srcdirs'}->{$k} = "$me->{'topdir'}/packaging_tools";
      next;
    }

   my $n = get_mask($k);

    my @candidates = grep { m!$n! } @dirs;

    die "ERROR: Could not find $n\n" if ! @candidates;

    $me->{'srcdirs'}->{$k} = "$supportdir/$candidates[0]";
#    print "    $supportdir/$candidates[0]\n";

  }
}


sub get_keys {
  my ($me) = @_;
  my @list;

  if (defined $me->{'buildlist'}) {
    @list = grep { $_  ne 'zlib' and $_ ne 'core' } @{ get_key_list() };
    return \@list;
  }

  @list = grep { $_  ne 'zlib' and $_ ne 'core' and $_ ne 'gpt' } 
    @{ get_key_list() };
  return \@list;
}



1;
__END__
