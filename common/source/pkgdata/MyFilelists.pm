package MyFilelists;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Grid::GPT::Filelist;
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
  my $me = {};
  bless $me, $class;
  $me->{'filelist'} = new Grid::GPT::Filelist((%arg));
  return $me;
}

sub pgm_files {
  my $self = shift;
  $self->{'filelist'}->extract_programs();
  $self->{'filelist'}->add_package_metadata_files('pgm');
  my $list = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();
  return $list;
}

sub rtl_files {
  my $self = shift;
  $self->{'filelist'}->flavored_files();
  $self->{'filelist'}->extract_dynamic_libs();
  $self->{'filelist'}->add_package_metadata_files('rtl');
  my $list = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();
  return $list;
}

sub dev_files {
  my $self = shift;
  my $result = [];

  $self->{'filelist'}->flavored_files();
  $self->{'filelist'}->extract_static_libs();
  my $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  $self->{'filelist'}->flavored_files();
  $self->{'filelist'}->extract_libtool_libs();
  $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  $self->{'filelist'}->flavored_headers();
  $self->{'filelist'}->add_package_metadata_files('dev');
  $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();
  return $result;
}

sub hdr_files {
  my $self = shift;
  $self->{'filelist'}->noflavor_headers();
  $self->{'filelist'}->add_package_metadata_files('hdr', 'noflavor');
  my $list = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();
  return $list;
}

sub data_files {
  my $self = shift;
  $self->{'filelist'}->extract_data();
  $self->{'filelist'}->add_package_metadata_files('data', 'noflavor');
  my $list = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();
  return $list;
}

sub doc_files {
  my $self = shift;
  $self->{'filelist'}->extract_docs();
  $self->{'filelist'}->add_package_metadata_files('doc', 'noflavor');
  my $list = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();
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
