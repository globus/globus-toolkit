package Grid::GPT::SetFunctions;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);


# set the version for version checking
$VERSION                    = 0.01;


sub remove_pkgs {
  my ($list, $removes) = @_;
  my @pruned;
  for my $p (@$list) {
    push @pruned, $p 
      if ! grep { $p->is_same($_) } @$removes;
    }
  
  return \@pruned;

}

sub remove_dups {
  my ($list) =@_;
  my @pruned;
  for my $p (@$list) {
    push @pruned, $p 
      if ! grep { $p->is_same($_) } @pruned;
    }

  return \@pruned;
}

sub _init
{

  my %set = (
             replacements     => undef,
             conflicts     => undef,
             downgrades    => undef,
             added     => undef,
             untouched => undef,
             replaced  => undef,
            );

  my ($me, %args) = @_;

  for my $k (keys %set) {
    $me->{$k} = $set{$k};
  }

  $me->{'lists'} = [ keys %set ];
  $me->{'force'} = $args{'force'};
  $me->{'filter'} = $args{'filter'};
  $me->{'log'} = $args{'log'};
  $me->_init_lists();
}

sub compare
{
  my ($me, %args) = @_;
  my $replace_set = $args{'replacements'}->get_name_version_list();
  my $mylist = $me->get_name_version_list();
  my $loose = $args{'2xbundle'};
#  print "Replacements:\n";
#  $args{'replacements'}->printtable();

#  print "Mylist:\n";
#  $me->printtable();

  $me->_init_lists();

  for my $r (@{$replace_set})
  {
    $me->{'log'}->debug("evaluating: " . $r->label() . "-" .
      $r->version_label() . "\n");

    my @same_names = grep { $r->name() eq $_->name() } @$mylist
;

    for my $n(@same_names) {

      $me->{'log'}->debug( $n->label() . "-" .
                           $n->version_label() . 
                           " has the same name as " .
                           $r->label() . "-" . 
                           $r->version_label() . "\n");
    }

    my (@replacements, @conflicts, @downgrades, @added);


    if (defined $me->{'filter'}) {
      my $results = &{$me->{'filter'}}(replacer => $r, 
                                       loose => $loose,
                                       candidates => \@same_names);

      @replacements = @{$results->{'replacements'}};
      @conflicts = @{$results->{'conflicts'}};
      @downgrades = @{$results->{'downgrades'}};
      @added = @{$results->{'added'}};

      if (@added) {
        push @{$me->{'added'}}, $r;
        next;
      }

    } else {

      # its gotta be bundles

      if (! @same_names) {
        push @{$me->{'added'}}, $r;
      }

      my @newer = map { {replacer => $r, replacee => $_}} 
        grep { $r->{'Version'}->is_newer($_->{'Version'})} 
          @same_names;

      for my $n(@newer) {

        my ($re, $rp) = ($n->{'replacee'},$n->{'replacer'});
        $me->{'log'}->debug( $rp->label() . "-" . $rp->version_label() . " is newer than " . 
          $re->label() . "-" . $re->version_label() . "\n");
      }


     my @older = map { {replacer => $r, replacee => $_}} 
        grep { $_->{'Version'}->is_newer($r->{'Version'})} 
          @same_names;

      for my $n(@older) {

        my ($re, $rp) = ($n->{'replacee'},$n->{'replacer'});
        $me->{'log'}->debug( $rp->label() . "-" . $rp->version_label() . " is older than " . 
          $re->label() . "-" . $re->version_label() . "\n");
      }

      if (defined $me->{'force'}) {
        @replacements = (@newer, @older);
      } else {
        @replacements = @newer;
        @conflicts = @older;
      }
    }

    for my $n(@replacements) {

      my ($re, $rp) = ($n->{'replacee'},$n->{'replacer'});
      $me->{'log'}->debug( $re->label() .  "-" . $re->version_label() . " is replaced by " . 
        $rp->label() ."-" . $rp->version_label() . "\n");
    }

    for my $n(@conflicts) {

      my ($re, $rp) = ($n->{'replacee'},$n->{'replacer'});
      $me->{'log'}->debug( $rp->label() . "-" . $rp->version_label() . " conflicts with " . 
        $re->label() ."-" . $re->version_label() . "\n");
    }

    for my $n(@downgrades) {

      my ($re, $rp) = ($n->{'replacee'},$n->{'replacer'});
      $me->{'log'}->debug( $rp->label() . "-" . $rp->version_label() . " is a downgrade of " . 
        $re->label() ."-" . $re->version_label() . "\n");
    }

    push @{$me->{'replacements'}},  @replacements;
    push @{$me->{'conflicts'}},  @conflicts;
    push @{$me->{'downgrades'}},  @downgrades;

  }


  for my $o (@$mylist) {

    push @{$me->{'untouched'}}, $o 
      if ! grep {$o->is_same($_->{'replacee' })} 
        (@{$me->{'replacements'}}, @{$me->{'conflicts'}});
  }

  @{$me->{'replaced'}} = map { $_->{'replacee'} } @{$me->{'replacements'}};
}

sub intersect
{
  my ($me, %args) = @_;
  my $other_set = $args{'other'}->get_name_version_list();
  my $mylist = $me->get_name_version_list();
  my @intersections;

  for my $o (@$mylist)
  {
    push @intersections, $o 
      if grep {$o->is_same($_) } @$other_set;
  }

  return \@intersections;
}

sub union
{
  my ($me, %args) = @_;
  my $other_set = $args{'other'}->get_name_version_list();
  my $mylist = $me->get_name_version_list();
  my @union;

  for my $o (@$mylist ,@$other_set)
  {
    push @union, $o 
      if grep { $o->is_same($_) } @union;
  }

  return \@union;

}

sub convert2set {
  my ($me, $list) = @_;

  my $set = new {ref($me)}(
                           force => $me->{'force'}, 
                           loose => $me->{'loose'}
                          );

  $set->convert_name_version_list2set($list);
  return $set;
}

sub _init_lists {
  my ($me) = @_;

  for my $l (@{$me->{'lists'}}) {
    $me->{$l} = [];
  }
}

sub printtable {
  my ($me) = @_;

  for my $l (@{$me->{'lists'}}) {

    print "$l\n";

    for my $p (@{$me->{$l}}) {
      if ($l eq 'conflicts' or $l eq 'downgrades' or $l eq 'replacements') {
        my $replacer = "$p->{'replacer'}->{'Name'}";
        
        $replacer .= "-" . $p->{'replacer'}->{'Version'}->version_label() 
            if defined $p->{'replacer'}->{'Version'};
        
        my $replacee = "$p->{'replacee'}->{'Name'}";
        $replacee .=  "-" . $p->{'replacee'}->{'Version'}->version_label()
          if defined $p->{'replacee'}->{'Version'};
        
        print "replace $replacee with $replacer\n";

      } else {
        print "$p->{'name'}";
        print "-",$p->version_label(),"\n"
          if defined $p->{'version'};
        print "\n";
      }
    }


  }

}
sub formtable {
  my ($me, $msg) = @_;

  for my $l (@{$me->{'lists'}}) {

    $msg .= "===$l===\n";

    for my $p (@{$me->{$l}}) {
      if ($l eq 'conflicts' or $l eq 'downgrades' or $l eq 'replacements') {
        my $replacer = $p->{'replacer'}->label();
        $replacer .= "-" . $p->{'replacer'}->version_label(); 
        
        my $replacee = $p->{'replacee'}->label();
        $replacee .=  "-" . $p->{'replacee'}->version_label();
        
        $msg .= "replace $replacee with $replacer\n";

      } else {
        $msg .= $p->label();
         $msg .= "-" . $p->version_label();
        $msg .=  "\n";
      }
    }


  }

  return $msg;
}

sub get_results
{
  my ($me, $list) = @_;

  return $me->{$list};
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




