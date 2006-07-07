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

# Add la files to flavored rtl files
sub rtl_files {
  my $self = shift;
  my $result = [];

  $result = $self->SUPER::rtl_files();

  $self->{'filelist'}->extract_libtool_libs();
  my $list = $self->{'filelist'}->get_list();
  push @$result, @$list;
  $self->{'filelist'}->reset();

  return $result;
}

# remove libtool libs from flavored dev files
sub dev_files {
  my $self = shift;
  my $list1 = [];
  my $list2 = [];
  my $result = [];

  # normal dev_files
  $list1 = $self->SUPER::dev_files();

  # la files
  $self->{'filelist'}->extract_libtool_libs();
  $list2 = $self->{'filelist'}->get_list();
  $self->{'filelist'}->reset();

  # remove la from result list
  OUTER: foreach my $t1 (@{$list1})
  {
      foreach my $t2 (@{$list2})
      {
          if ($t1 eq $t2)
          {
              next OUTER;
          }
      }
      push @{$result}, $t1;
  }

  return $result;
}

1;
