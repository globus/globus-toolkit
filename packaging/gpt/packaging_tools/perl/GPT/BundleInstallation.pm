package Grid::GPT::BundleInstallation;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Grid::GPT::V1::Bundle;
require Grid::GPT::BundleSet;
require Grid::GPT::Locations;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BundleSet);

sub new
{
  my ($class, %args) = @_;
  my $me = {
            locations => $args{'locations'},
           };

  bless $me, $class;

  $me->Grid::GPT::BundleSet::_init(%args);
  $me->load_installation() if !defined $args{'noload'};

  return $me;
}

sub load_installation
{
  my ($me) = @_;

my $cnt = 0;

  opendir(PKGDIR, $me->{'locations'}->{'bundledir'});
  my @bndldir = grep {$_ ne 'setup'} grep { ! m!^\.! }readdir PKGDIR;
  closedir PKGDIR;

  my $filelist_funcs;

  for my $bd (@bndldir)
  {
    my $dir       = "$me->{'locations'}->{'bundledir'}/$bd";

    opendir(PKGDIR, $dir);
    my @bndlfile  = grep { m!\.gpt-bundle\.xml$! } readdir PKGDIR;
    closedir PKGDIR;

    for my $b (@bndlfile) 
    {
      my $file    = "$dir/$b";
      $me->add_bundle(def_file => $file);
    }
  }
}


sub check_all_bundles_integrity
{
  my ($self, %args) = @_;

  my $inst          = $args{'installation'};

  for my $b (@{$self->{'bundles'}})
  {
    print "Bundle: $b->{'Name'}\n";
    $b->compare_bundle_2_installation( inst => $inst );
    print "\n";
  }
}

sub check_bundle_integrity
{
  my ($self, %args) = @_;

  my $bundle        = $self->find_bundle( bundle => $args{'bundle'} ); 
  my $inst          = $args{'inst'};

  $bundle->compare_bundle_2_installation( inst => $inst ); 
  print "\n";
}

sub check_bundle_package_overlap
{
  my ($self, %args) = @_;

  my $bad           = 0;
  my @pkgs;

  my $bundle        = $self->find_bundle( bundle => $args{'bundle'} ); 

  @pkgs             = $self->find_bundle( bundle => $args{'bundle'} )->getFullBundleIncludedPackageList() if( defined($args{'bundle'}) );

  if( defined($args{'packages'}) )
  {
    for my $r ($args{'packages'})
    {
      for my $d (@$r)
      {
        push @pkgs, $d;
      }
    }
  }

  for my $b (@{$self->{'bundles'}}) 
  {
    next if( $b->{'Name'} eq $args{'bundle'} );

    for my $p (@pkgs) 
    {
      if( $b->find_package( package => $p ) )
      {
        $bad        = 1;
        print "Overlap Bundle $b->{'Name'} Package $p->{'Name'}-$p->{'Flavor'}-$p->{'Type'} V.$p->{'Version'}\n";
      }
    }
  }    
  return( $bad );
}

sub good_to_replace
{
  my ($self, %args)   = @_;
  my @conflictPkg;
  my $bad             = 0;

  my $new_bundle      = $args{'bundle'};
  my $installedBundle = $self->find_bundle( bundle => $new_bundle->{'Name'} );

  if( defined($installedBundle) )
  {
    my @conflict      = $installedBundle->compare_bundle_2_bundle( 
                                                      bundle   => $new_bundle );
    if( @conflict )
    {
      my $bad         = $self->check_bundle_package_overlap( 
                                                      packages => \@conflict );

      for my $cp (@conflict)
      {
        my $p         = $installedBundle->find_package( package => $cp );

        if( defined( $p ) )
        {
          push @conflictPkg, $p;
        }
      }
    }
  }
  return $bad, @conflictPkg;
}

sub get_installed_bundles
{
  my ($self) = @_;

  return $self->{'bundles'};
}
  
sub check_bundle_version
{
  my ($self) = @_;

  my @oldStyle; 
  my @newStyle;

  for my $b (@{$self->{'bundles'}})
  {
    if( $b->{'BundleVersion'} eq 'EMPTY' || !defined($b->{'BundleVersion'}) )
    {
      push @oldStyle, $b->{'Name'};
    }
    else
    {
      push @newStyle, $b->{'Name'};
    }
  }
  return( \@oldStyle, \@newStyle );
}

sub find_matching_package
{
  my ($self, %args) = @_;

  my $bundle        = $args{'package'};

  return if !defined $self->{'bundles'};

  for my $b (@{$self->{'bundles'}})
  {
    if( $b->{'Name'} eq $bundle )
    {
##      return( $b->getBundleIncludedPackageList() );
      my @packageList;
      my $pl = $b->getFullBundleIncludedPackageList();
      for my $p (@{$pl})
      {
        my $pkg = "$p->{'Name'}-$p->{'Flavor'}_$p->{'Type'}";
        push @packageList, $pkg;
      }
      return @packageList;
    }
  }
}


  
sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
  } 
  if (@_) {
    return $self->{$name} = shift;
  } else {
    return $self->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
