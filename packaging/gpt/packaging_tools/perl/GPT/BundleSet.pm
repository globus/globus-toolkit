package Grid::GPT::BundleSet;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
require Grid::GPT::SetFunctions;
require Grid::GPT::PkgDefsSet;

@ISA = qw(Exporter Grid::GPT::SetFunctions);

# set the version for version checking
$VERSION                    = 0.01;
my @set;

sub new
{
  my ($class, %args) = @_;
  my $me = {};
  bless $me, $class;
  $me->_init(%args);

  return $me;
}

sub _init
{
  my ($me, %args) = @_;
  $me->{'tmpdir'} = $args{'tmpdir'};
  $me->{'bundles'} = [];
  $me->{'log'} = $args{'log'},
  $me->Grid::GPT::SetFunctions::_init(%args);
}

sub add_bundle 
{
  my ($self, %args)      = @_;
  my $bundle             = $args{'bundle'};
  my $tmp_bndl;


  if (defined $args{'def_file'}) {
    $bundle = new Grid::GPT::V1::Bundle(tmpdir => $self->{'tmpdir'},
                                        log => $self->{'log'},
                                       );
    $bundle->read_metadata_file($args{'def_file'});
    $bundle->create_pkgdefs_set();
  }

  if (defined $args{'tarfile'}) {
    $bundle = new Grid::GPT::V1::Bundle(tmpdir => $self->{'tmpdir'},
                                        log => $self->{'log'},
                                       );
    $bundle->read_bundle_from_tar(file => $args{'tarfile'});
    $bundle->create_pkgdefs_set();
  }

  push @{$self->{'bundles'}}, $bundle;
}

sub unpack_bundles {
  my ($self) = @_;

  for my $b (@{$self->{'bundles'}}) {

    $b->unpack_tar_bundle();
  }
}

sub remove_bundle
{
  my ($self, %args)      = @_;
  my $bundle             = $args{'bundle'};

  my @set = grep {! $_->is_same($bundle)} @{$self->{'bundles'}};

  $self->{'bundles'} = \@set;
  
} 

sub get_new_style
{
  my ($self) = @_;

  return [ grep { ! $_->is_old_style() } @{$self->{'bundles'}} ];
}

sub get_old_style
{
  my ($self) = @_;

  return [ grep { $_->is_old_style() } @{$self->{'bundles'}} ];
}

sub find_bundle
{
  my ($self, %args) = @_;

  my $bundle_name   = $args{'bundle'};

  my @matches = grep { $_->{'Name'} eq $bundle_name } @{$self->{'bundles'}};

  return undef if ! @matches;
  return $matches[0];
}

sub what_bundles
{
  my ($self) = @_;
  my @blist = map { ($_->{'Name'} . " ver: " . $_->version_label() ) } 
    @{$self->{'bundles'}};
  return \@blist;
}

sub list_packages_for_bundle
{
  my ($self, %args) = @_;

  my $bundle        = $self->find_bundle( bundle => $args{'bundle'} ); 

##  return( $bundle->getBundleIncludedPackageList() );
      my @packageList;
      my $pl = $bundle->getFullBundleIncludedPackageList();
      for my $p (@{$pl})
      {
        my $pkg = "$p->{'Name'}-$p->{'Flavor'}_$p->{'Type'}";
        push @packageList, $pkg;
      }
      return @packageList;
}

sub find_package {

  my ($self, %args) = @_;

  my @matched_bundles;

  for my $b (@{$self->{'bundles'}}) {

    my $matches = $b->{'PkgDefs'}->query(%args);
    my @matches = grep { $_->{'version'}->is_equal($args{'version'})} @$matches;
    push @matched_bundles, $b if @matches;
  }
  return \@matched_bundles;
}

sub get_name_version_list 
{
  my ($me) = @_;

  return $me->{'bundles'};
}

sub convert_name_version_list2set 
{
  my ($me, $list) = @_;

  my $set = new Grid::GPT::BundleSet(
                                     tmpdir => $me->{'tmpdir'},
                                     force => $me->{'force'},
                                     loose => $me->{'loose'},
                                    );
  for $b (@$list) {
    $set->add_bundle(bundle => $b);
  }
  return $set;
}

sub check_for_package_conflicts {
  my ($me, $bundle) = @_;

  my $pkgset = new Grid::GPT::PkgDefsSet(
                                        tmpdir => $me->{'locations'}->{'tmpdir'},
                                        force => $me->{'force'},
                                    );

  for $b (@{$me->{'bundles'}}) {

    for my $p (@{$b->{'PkgDefs'}->{'pkgs'}}) {
      $pkgset->add_package(pkgnode => $p);
    }

  }

  $pkgset->compare(replacements => $bundle->{'PkgDefs'});

  my @returns = (@{$pkgset->{'replacements'}} , @{$pkgset->{'conflicts'}} );
  return @returns;

}

sub get_removed_packages {
    my ($me) = @_;

    my @goners;
    my @pairs = @{$me->{'replacements'}};
    for my $b (@pairs) {
      for my $p( @{$b->{'replacee'}->{'PkgDefs'}->{'pkgs'}}) {
        my $matches = 
          $b->{'replacer'}->{'PkgDefs'}->query(
                                               pkgname => $p->pkgname(),
                                               flavor => $p->flavor(),
                                               pkgtype => $p->pkgtype(),
                                              );

        push @goners, $p if ! @$matches;
      }
    }
    return \@goners;
}

sub get_replaced_packages {
    my ($me) = @_;

    my @replace;
    my @pairs = @{$me->{'replacements'}};
    for my $b (@pairs) {
      for my $p( @{$b->{'replacee'}->{'PkgDefs'}->{'pkgs'}}) {
        my $matches = 
          $b->{'replacer'}->{'PkgDefs'}->query(
                                               pkgname => $p->pkgname(),
                                               flavor => $p->flavor(),
                                               pkgtype => $p->pkgtype(),
                                              );

        push @replace, $p if @$matches;
      }
    }
    return \@replace;
}

sub printtable {
  my ($me) = @_;

  print "Bundles: \n";

  for my $b(@{$me->{'bundles'}}) {
    print "$b->{'Name'}";
    print "-",$b->version_label(),"\n";
  }

  $me->Grid::GPT::SetFunctions::printtable();
}

sub formtable {
  my ($me, $msg) = @_;

  $msg .= "Bundles: \n";

  for my $b(@{$me->{'bundles'}}) {
    $msg .=  "\t$b->{'Name'}";
    $msg .=  "-" . $b->version_label() . "\n";
  }

  return $me->Grid::GPT::SetFunctions::formtable($msg);
}


sub AUTOLOAD 
{
  use vars qw($AUTOLOAD);

  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;

  $name =~ s/.*://;   # strip fully-qualified portion

  unless (exists $self->{$name} ) 
  {
    croak "Can't access `$name' field in object of class $type";
  }

  if (@_) 
  {
    return $self->{$name} = shift;
  } 
  else 
  {
    return $self->{$name};
  }
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)
1;
__END__
