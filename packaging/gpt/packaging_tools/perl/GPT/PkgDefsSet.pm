package Grid::GPT::PkgDefsSet;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

require Grid::GPT::PkgDefNode;
require Grid::GPT::BaseTable;
require Grid::GPT::SetFunctions;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseTable Grid::GPT::SetFunctions);
sub _init {
  my ($me, %args)  = @_;
  $me->{'pkgs'} = [];
  $me->{'log'} = $args{'log'};
  $me->{'indexes'} = ['pkgname','flavor','pkgtype'];

  $me->Grid::GPT::SetFunctions::_init
    (%args, 
     filter => sub {return $me->filter_replacement_pkgs(@_);}
    );

}


sub query {
  my ($me, %args) = @_;
  my $list = $me->Grid::GPT::BaseTable::query(%args);


  my @sorted = sort {
    $a->pkgname() cmp $b->pkgname() ||
      $a->flavor() cmp $b->flavor() ||
        $a->pkgtype() cmp $b->pkgtype()
  } @$list;

  return \@sorted;
}
sub add_pkgnode {
  my ($me, %args) = @_;

  my $node = $args{'node'};
  $me->add_package(
                   pkgname => $node->pkgname(),
                   flavor => $node->flavor(),
                   pkgtype => $node->pkgtype(),
                   version => $node->{'depnode'}->{'Version'},
                   bundle => $args{'bundle'},
                   pkgnode => $node,
                  );

}

sub add_bundle {
  my ($me, %args) = @_;

  my $bundle = $args{'bundle'};

  for my $p (@{$bundle->{'PkgDefs'}->{'pkgs'}}) {
    $me->add_package(pkgdef => $p);
  }

}


sub add_package {
  my ($me, %args) = @_;

  my $object = $args{'pkgdef'};
  $object = new Grid::GPT::PkgDefNode(
                                      pkgname => $args{'pkgname'},
                                      flavor => $args{'flavor'},
                                      pkgtype => $args{'pkgtype'},
                                      version => $args{'version'},
                                      bundle => $args{'bundle'},
                                      pkgnode => $args{'pkgnode'},
                                      log => $me->{'log'},
                                     )
    if ! defined $object;

  my $exists = $me->get_package(pkgnode => $object);
  if (defined $exists) {
    return;
  }

  $me->add_object(depnode => $object,
                  pkgname => $object->pkgname(),
                  flavor => $object->flavor(),
                  pkgtype => $object->pkgtype(),
                  );

  push @{$me->{'pkgs'}}, $object;

  return $object;
}

sub remove_package {
  my ($me, %args) = @_;

  my $object = $args{'pkgnode'};
  my $exists = $me->get_package(pkgnode => $object);
  return if (! defined $exists);

  $me->Grid::GPT::BaseTable::remove_package( pkgname => $object->pkgname(),
                                             flavor => $object->flavor(),
                                             pkgtype => $object->pkgtype(),
                                           );

  my @newlist = grep { ! $object->is_same($_) } @{$me->{'pkgs'}};

  $me->{'pkgs'} = \@newlist;
}

sub remove_pkgs {
  my ($me, %args) = @_;


  for my $p (@{$args{'pkgs'}}) {
    $me->remove_pkg(pkgnode => $p);
  }

#  $me->printtable();
}

sub get_package {
  my ($me, %args) = @_;
  my ($pkgname, 
      $flavor, 
      $pkgtype) = ($args{'pkgname'} || 'ANY', 
                   $args{'flavor'} || 'ANY',
                   $args{'pkgtype'} || 'ANY');

  if (defined $args{'pkgnode'}) {
    my @pkgs = grep {$_->is_same($args{'pkgnode'}) } @{$me->{'pkgs'}};
    return $pkgs[0];
  }
    

  return undef if ! defined $me->{'table'}->{$pkgname};
  return undef 
    if ! defined $me->{'table'}->{$pkgname}->{$flavor};  
  return 
    $me->{'table'}->{$pkgname}->{$flavor}->{$pkgtype};  
}

sub get_name_version_list {
  my ($me) = @_;

  return $me->pkgs();

}

sub convert_name_version_list2set {

  my ($me, $list) = @_;

  my $pkgset = new Grid::GPT::PkgDefsSet;

  for my $l (@$list) {
    $pkgset->add_package(pkgnode => $l);
  }

  return $pkgset;

}

sub filter_replacement_pkgs {
  my ($me, %args) = @_;
  my @replacements;
  my @conflicts;
  my @downgrades;
  my @added;
  my $do_not_install = 0;
  my $add = 0;

  my $p = $args{'replacer'};
  for my $c (@{$args{'candidates'}}) {

    my $test = $c->is_replacable(force => $me->{'force'},
                                          other => $p,
                                          loose => $args{'loose'},
                                         );
    if ($test eq 'REPLACE') {
      $me->{'log'}->debug("\tREPLACE");
      push @replacements, { replacer => $p, replacee => $c};
      $add = 0;
      next;
    }

    if ($test eq 'CONFLICT') {
      $me->{'log'}->debug("\tCONFLICT");
      push @conflicts, { replacer => $p, replacee => $c};
      $add = 0;
      next;
    }

    if ($test eq 'DOWNGRADE') {
      $me->{'log'}->debug("\tDOWNGRADE");
      push @downgrades, { replacer => $p, replacee => $c};
      $add = 0;
      next;
    }

    if ($test eq 'ADD') {
      $me->{'log'}->debug("\tADD");
      $add++;
      next;
    } 
    if ($test eq 'DO_NOT_INSTALL') {
      $me->{'log'}->debug("\tDO_NOT_INSTALL");
      $do_not_install++;
      next;
    } 
    $me->{'log'}->debug("\tIGNORE");
  }


  if (! @conflicts and ! @downgrades and ! @replacements and 
      ! $do_not_install) {

    $me->{'log'}->debug("\tADD") if ! $add;

    push @added, $p;
  }

  return {
          replacements => \@replacements, 
          conflicts => \@conflicts, 
          downgrades => \@downgrades, 
          added => \@added
         };
}

sub printtable {
  my ($me) = @_;

  print "Packages: \n";

  for my $p (@{$me->{'pkgs'}}) {
    print $p->label(), "-", $p->version_label();
    print " from bundle ";
    if ($p->{'bundle'} ne "NONE") {
      print $p->{'bundle'}->Name(),"-"; 
      print $p->{'bundle'}->version_label(),
    } else {
      print "NONE";
    }
    print    "\n";
  }
  $me->Grid::GPT::SetFunctions::printtable();
}

sub formtable {
  my ($me, $msg) = @_;

  $msg .= "Packages: \n";

  for my $p (@{$me->{'pkgs'}}) {
    $msg .= $p->label() .  "-" . $p->version_label();
    $msg .=  " from bundle ";
    if ($p->{'bundle'} ne "NONE") {
      $msg .= $p->{'bundle'}->Name() . "-"; 
     $msg .=  $p->{'bundle'}->version_label(),
    } else {
      $msg .= "NONE";
    }
    $msg .= "\n";
  }
  return $me->Grid::GPT::SetFunctions::formtable($msg);
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
