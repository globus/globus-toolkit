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

# removed python modules from flavored rtl files
sub rtl_files {
  my $self = shift;
  my $result = [];
  $self->{'filelist'}->flavored_files();
  $self->{'filelist'}->extract_dynamic_libs();
  $self->{'filelist'}->add_package_metadata_files('rtl');
  my $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  return $result;
}

# added perl modules to unflavored data
sub data_files {
  my $self = shift;
  my $result = [];
  $self->extract_python_modules($self->{'filelist'});
  $self->{'filelist'}->add_package_metadata_files('data', 'noflavor');

  my $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  $self->{filelist}->extract_data();
  $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  return $result;
}

sub extract_python_modules {
    my $self = shift;
    my $filelist = shift;
    my @newlist;

    for (@{$filelist->{'list'}}) {
        if ($_->{'name'} =~ m!\.py$! and $_->{'dir'} =~ m!/lib/!) {
            push (@newlist, $_);
        }
    }
    $filelist->{'list'} = \@newlist
}

1;
