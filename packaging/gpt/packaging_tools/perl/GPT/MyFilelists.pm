package Grid::GPT::MyFilelists;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::FilelistSort;
use strict;

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
            filelist => new Grid::GPT::FilelistSort((%arg)),
            mangling => $arg{'mangling'},
          };
  bless $me, $class;
  return $me;
}

sub pgm_files {
  my $me = shift;
  my $result = [];
  $me->{'filelist'}->extract_programs();
  $me->{'filelist'}->add_package_metadata_files('pgm');
  my $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  $me->{'filelist'}->extract_setup_files();
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  return $result;
}

sub pgm_static_files {
  my $me = shift;
  my $result = [];
  $me->{'filelist'}->extract_programs();
  $me->{'filelist'}->add_package_metadata_files('pgm_static');
  my $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  $me->{'filelist'}->extract_setup_files();
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  return $result;
}

sub rtl_files {
  my $me = shift;
  my $result = [];
  $me->{'filelist'}->flavored_files() if defined $me->{'mangling'};
  $me->{'filelist'}->extract_dynamic_libs();
  $me->{'filelist'}->add_package_metadata_files('rtl');
  my $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();

  $me->{'filelist'}->extract_perl_modules();
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  return $result;
}

sub dev_files {
  my $me = shift;
  my $result = [];

  $me->{'filelist'}->flavored_files() if defined $me->{'mangling'};
  $me->{'filelist'}->extract_static_libs();
  my $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();

  $me->{'filelist'}->flavored_files() if defined $me->{'mangling'};
  $me->{'filelist'}->extract_libtool_libs();
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();

  $me->{'filelist'}->flavored_headers() if defined $me->{'mangling'};
  $me->{'filelist'}->add_package_metadata_files('dev');
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();

  $me->{'filelist'}->noflavor_headers();
  $list = $me->{'filelist'}->get_list();
  push @$result, @$list;
  $me->{'filelist'}->reset();
  return $result;
}

sub data_files {
  my $me = shift;
  $me->{'filelist'}->extract_data();
  $me->{'filelist'}->add_package_metadata_files('data', 'noflavor');
  my $list = $me->{'filelist'}->get_list();
  $me->{'filelist'}->reset();
  return $list;
}

sub doc_files {
  my $me = shift;
  $me->{'filelist'}->extract_docs();
  $me->{'filelist'}->add_package_metadata_files('doc', 'noflavor');
  my $list = $me->{'filelist'}->get_list();
  $me->{'filelist'}->reset();
  return $list;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Filelist - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Filelist;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Filelist was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
