use Grid::GPT::Filelist;
use Grid::GPT::MyFilelists;
use strict;

package MyFilelists;

use vars qw(@ISA);

@ISA = qw(Grid::GPT::MyFilelists);

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $me = $class->SUPER::new(@_);
  bless $me, $class;
  return $me;
}

# don't put files in /test into the data package
sub data_files {
  my $self = shift;
  my $result = [];
  my $list;


  $self->{filelist}->extract_data();
  $self->{'filelist'}->add_package_metadata_files('data', 'noflavor');

  $list = $self->{'filelist'}->get_list();

  foreach(@$list)
  {
      if($_ !~ m|^/test|)
      {
	  push @$result, $_;

      }
  }
  $self->{'filelist'}->reset();

  return $result;
}

1;
