package Grid::GPT::Setup;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);


# This module is included by scripts outside of GPT and so require the 
use Config;
# @INC fiddling
my $gpt_path = $ENV{GPT_LOCATION};
@INC = ("$gpt_path/lib/perl", "$gpt_path/lib/perl/$Config{'archname'}", @INC);

require Grid::GPT::Installation;
require Grid::GPT::Locations;
require Grid::GPT::V1::Version;
require Grid::GPT::FilelistFunctions;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);
@EXPORT      = qw(&open_metadata_file &func2 &func4);
%EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],


sub new {
    my ($that, %args)  = @_;
    my $class = ref($that) || $that;
    my $me  = {
		 package_name => $args{'package_name'},
                 setup_name => $args{'setup_name'},
                 setup_version => $args{'setup_version'},
                 locations => new Grid::GPT::Locations(
                                                       installdir => 
                                                       $args{'globusdir'}
                                                      ),

		};
    bless $me, $class;
    $me->_init();
    return $me;
}

sub _init {
  my ($me) = @_;
  my $installation = new Grid::GPT::Installation(locations => $me->{'locations'});

  my $cands = $installation->query(setupname => $me->{'setup_name'}, 
                                   pkgname =>$me->{'package_name'});

  if (defined $me->{'setup_version'}) {
    my $version = new Grid::GPT::V1::Version(label => $me->{'setup_version'});
    @$cands = grep {$version->is_equal($_->version())} @$cands;
  }

  die "ERROR: Setup package not found. Looking for:
       name=$me->{'package_name'},setup_name=$me->{'setup_name'}, and \
setup version=$me->{'setup_version'}\n" if ! @$cands;

  if (@$cands > 1) {

    @$cands = grep { $_->pkgtype() =~ m!pgm! } @$cands;

    if (@$cands > 1) {
      print STDERR "WARNING: Ambiguous Setup package name:
         name=$me->{'package_name'},setup_name=$me->{'setup_name'}, and \
setup version=$me->{'setup_version'}

         The following packages that were found. The first one will be used:\n";
      for my $c(@$cands) {
        print "              ", $c->label(), "\n";
      }
    }
  }
  $me->{'pkg'} = $cands->[0];
}


sub finish {
  my ($me) = @_;
  my $setupname = $me->{'pkg'}->setupname();

  my $setupdir = $me->{'locations'}->setupdir();

  $setupdir .= "/" . $me->{'pkg'}->setupname();

  Grid::GPT::FilelistFunctions::mkinstalldir($setupdir);

  my $filename = "$setupdir/" . $me->{'pkg'}->pkgname() . ".gpt";

  if (-f $me->{'pkgfile'}) {
    my $result = system("cp $me->{'pkgfile'} $filename");
  } else {
    $me->{'pkg'}->{'depnode'}->output_metadata_file($filename);
  }

}

sub DESTROY {}

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::Setup - Perl extension for writing setup package metadata

=head1 SYNOPSIS

  use Grid::GPT::Setup;
  my $metdata = new Grid::GPT::Setup(package_name =>'globus_trusted_ca_setup', 
                                     organization => 'globus');

  $metdata->finish();

=head1 DESCRIPTION

I<Grid::GPT::Setup> is used to write setup package metadata. The
metadata that is written indicates to the packaging tools that the
package has been set up. The library should be included in all setup
scripts.  The library has been set up as a perl object to allow for
future expansion

=over 4

=item new

Creates a new object with the package_name.  The function also reads
the package metadata file for the remaining information.

=item finish

Writes metatdata into
$GLOBUS_LOCATION/etc/globus_packages/setup/<setup_format_name> to
indicate that the setup is complete.

=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) GRID::GPT::VERSION(1).

=cut
