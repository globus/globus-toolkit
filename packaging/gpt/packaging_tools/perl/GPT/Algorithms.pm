package Grid::GPT::Algorithms;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA);

require Grid::GPT::BundleInstallation;
require Grid::GPT::V1::Bundle;
require Grid::GPT::BundleSet;
require Grid::GPT::Installation;
require Grid::GPT::PkgFileName;
require Grid::GPT::PkgDist;
require Grid::GPT::PkgSet;
require Grid::GPT::PkgDefsSet;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

{
  my %pkgtype2depenv = (
                        'data'       => ['Runtime', 'Setup'],
                        'doc'        => ['Runtime', 'Setup'],
                        'dev'        => ['Build'],
                        'pgm'        => ['Runtime','Setup'],
                        'pgm_static' => ['Runtime', 'Setup'],
                        'rtl'        => ['Runtime', 'Setup'],
                        'sdk'        => ['Build'],
                        'src'        => ['Build', 'Runtime', 'Setup'],
                       );

  sub pkgtype2depenv {
    return $pkgtype2depenv{$_};
  }

}

sub new {
  my ($that, %args)  = @_;
  my $class = ref($that) || $that;
  
  my $me  = {
             add => undef,
             remove => undef,
             ignore => undef,
             log => $args{'log'},
             force => $args{'force'},
             source => $args{'source'},
             locations => $args{'locations'},
            };

  bless $me, $class;
  $me->_init(%args);
  return $me;
}

sub _init {
  my ($me, %args) = @_;

  $me->{'bndlinst'} = new Grid::GPT::BundleInstallation(%args);
  $me->{'pkginst'} = new Grid::GPT::Installation(%args, with_filelists => 1);
  $me->{'namematch'} = new Grid::GPT::PkgFileName(%args);

}


sub update {
  my ($me, %args) = @_;
  my $inputs = $me->sort_input_files(inputs => $args{'files'});

  return undef if ! defined $inputs;

  my $bundle_results = $me->update_check_bundles(bundles => $inputs->{'bundles'});

  return undef if ! defined $bundle_results;

  

# Checking for package conflicts
  $me->dump_results(
                    new_bundles => [ 
                                    @{$bundle_results->{'replace'} }, 
                                    @{$bundle_results->{'add'}}
                                   ],
                    removed_bundles => $bundle_results->{'remove'},
                   );
# Create 2x bundle objects

  my $bundles2x = $me->_2xbundle2obj('2xbundles' => $inputs->{'2xbundles'});

  push @{$bundle_results->{'add'}}, @$bundles2x;

# Create unaffiliated package objects.

  my @to_install_pkgs = @{$inputs->{'pkgs'}};

  my $unaffiliated_pkgs = 
    new Grid::GPT::PkgDist(
                           pkgtars => 
                           \@to_install_pkgs,
                           with_filelists => 1,
                          );
  my $unaffiliated_pkgdefs = new Grid::GPT::PkgDefsSet(
                                                       force => $me->{'force'},
                                                       log => $me->{'log'},
                                                      );

  for my $p (@{$unaffiliated_pkgs->{'pkgs'}}) {
    $unaffiliated_pkgdefs->add_pkgnode(node => $p);
  }


# Check each replacement, added bundle, and 2x bundle for package conflicts

  my $pkg_results = $me->update_check_bundles2pkgs(
                                                   %$bundle_results,
                                                   pkgs => 
                                                   $unaffiliated_pkgdefs,
                                                  );
  return undef if ! defined $pkg_results;

  $me->dump_results(
                    new_bundles => [ 
                                    @{$bundle_results->{'replace'} }, 
                                    @{$bundle_results->{'add'}}
                                   ],
                    removed_bundles => $bundle_results->{'remove'},
                    new_packages =>$pkg_results->{'new_pkgs'},
                    removed_packages =>$pkg_results->{'remove_pkgs'},
                    force_removed_packages =>$pkg_results->{'force_remove_pkgs'},
                   );

#Check for conflicts with unaffiliated installed packages

  my $unaffiliated_pkg_results = 
    $me->update_check_bundles2unaffiliated(
                                           remove_pkgs =>
                                           $pkg_results->{'remove_pkgs'},
                                           new_pkgs =>
                                           $pkg_results->{'new_pkgs'},
                                          );

  return undef if ! defined $unaffiliated_pkg_results;


  my $remove_pkgs = new Grid::GPT::PkgDefsSet(
                                             );

  for my $p ( @{$unaffiliated_pkg_results->{'replaced_pkgs'}},
              @{$pkg_results->{'remove_pkgs'}}) {
    $remove_pkgs->add_package(pkgdef => $p);
  }


  $me->dump_results(
                    new_bundles => [ 
                                    @{$bundle_results->{'replace'} }, 
                                    @{$bundle_results->{'add'}}
                                   ],
                    removed_bundles => $bundle_results->{'remove'},
                    new_packages =>$unaffiliated_pkg_results->{'new_pkgs'},
                    removed_packages =>$remove_pkgs->pkgs(),
                    force_removed_packages =>$pkg_results->{'force_remove_pkgs'},
                   );

  $me->{'log'}->debug("+++ filtering remove packages +++\n");

  $remove_pkgs = $me->filter_remove_pkgs(
                                         pkgs => $remove_pkgs,
                                         bndls => 
                                         $bundle_results->{'remove'},
                                         nodeps => 1,
                                         force_pkgs =>
                                         $pkg_results->{'force_remove_pkgs'},
                                        ) if ! defined $me->{'force'};

  $me->dump_results(
                    new_bundles => [ 
                                    @{$bundle_results->{'replace'} }, 
                                    @{$bundle_results->{'add'}}
                                   ],
                    removed_bundles => $bundle_results->{'remove'},
                    new_packages =>$unaffiliated_pkg_results->{'new_pkgs'},
                    removed_packages =>$remove_pkgs->pkgs(),
                    force_removed_packages =>$pkg_results->{'force_remove_pkgs'},
                   );


  # Check for conflicts within the new packages

  my $new_conflict_free_pkgs = 
    $me->update_new_pkg_consistency_check(
                                          new_pkgs => 
                                          $unaffiliated_pkg_results->{'new_pkgs'},
                                         );
  return undef if ! defined $new_conflict_free_pkgs;


  $me->dump_results(
                    new_bundles => [ 
                                    @{$bundle_results->{'replace'} }, 
                                    @{$bundle_results->{'add'}}
                                   ],
                    removed_bundles => $bundle_results->{'remove'},
                    new_packages =>$new_conflict_free_pkgs,
                    removed_packages =>$remove_pkgs->pkgs(),
                    force_removed_packages =>$pkg_results->{'force_remove_pkgs'},
                   );

  # collect pkg distribution to be installed

  my $new_pkgs =  new Grid::GPT::PkgSet(
                                        with_filelists => 1,
                                       );


  for my $p (@$new_conflict_free_pkgs) {
    my $matches = $new_pkgs->query(
                                   pkgname => $p->pkgname(),
                                   flavor => $p->flavor(),
                                   pkgtype => $p->pkgtype(),

                                  );
    if (@$matches) {
      $new_pkgs->add_package(pkgnode => $matches->[0]);
      next;
    }

    my $bundle = $p->{'bundle'};

    if ($bundle eq "NONE") {

      $new_pkgs->add_package(pkgnode => $p->pkgnode()); 
      next;
    }

    if (! defined $bundle->{'Packages'}) {
      $bundle->unpack_tar_bundle();
    }
    $matches =  $bundle->{'Packages'}->query(
                                             pkgname => $p->pkgname(),
                                             flavor => $p->flavor(),
                                             pkgtype => $p->pkgtype(),
                                            );

    if (! @$matches) {
      print STDERR "ERROR: $bundle->{'tarfile'} is corrupted\n";
      print STDERR "Package ", $p->label(), " cannot be found\n";
      print "PkgDefs:\n";
      $bundle->{'PkgDefs'}->printtable();
      print "PkgDist:\n";
      $bundle->{'Packages'}->printtable();
      die;
    }

    $new_pkgs->add_package(pkgnode => $matches->[0]);
  }


  my @new_bundles = (@{$bundle_results->{'replace'}}, 
                     @{$bundle_results->{'add'}});

  my @removed_packages;

  for my $p (@{$unaffiliated_pkg_results->{'replaced'}}, 
             @{$remove_pkgs->{'pkgs'}}) {

    my $matches = $me->{'pkginst'}->query(
                                          pkgname => $p->pkgname(),
                                          flavor => $p->flavor(),
                                          pkgtype => $p->pkgtype(),
                                         );

    my @matches =
      grep { $p->{'version'}->is_equal($_->{'depnode'}->{'Version'})}
        @$matches;


    next if ! @matches;

    push @removed_packages,$matches[0];

  }

  # Check for file conflicts
  my $check = 
    $me->update_file_conflict_check(
                                    new_pkgs => $new_pkgs->{'pkgs'},
                                    remove_pkgs => \@removed_packages,
                                   );

  return undef if $check eq "FOUND_CONFLICTS";

  return { 
          new_bundles => \@new_bundles,
          removed_bundles => $bundle_results->{'remove'},
          removed_packages => \@removed_packages,
          new_packages => $new_pkgs->{'pkgs'},
         };
}

sub update_check_bundles {
  my ($me, %args) = @_;
  my @to_install_bundles = @{$args{'bundles'}};

  my $installed_bundleset;

  $installed_bundleset = 
    new Grid::GPT::BundleSet(
                             tmpdir => $me->{'locations'}->{'tmpdir'},
                             force => $me->{'force'},
                             log => $me->{'log'},
                            );


# Filter out 2x bundles for the update check.
  for my $b (@{$me->{'bndlinst'}->{'bundles'}}) {
    next if $b->is_old_style();
    $installed_bundleset->add_bundle(bundle =>$b);
  }


  my $msg = "+++installed bundle set+++\n";
  $msg .= $installed_bundleset->formtable();
  $me->{'log'}->debug($msg);
    
  my $to_install_bundleset = 
    new Grid::GPT::BundleSet(
                             tmpdir => $me->{'locations'}->{'tmpdir'},
                             log => $me->{'log'},
                             force => $me->{'force'},
                            );

  for my $b (@to_install_bundles) {
    $to_install_bundleset->add_bundle(tarfile => $b);
  }

  $msg = "+++to install bundle set+++\n";
  $msg .= $to_install_bundleset->formtable();
  $me->{'log'}->debug($msg);
    
  $me->{'log'}->debug("+++ compared installed bundles to new bundles +++\n");
  $installed_bundleset->compare(replacements => $to_install_bundleset);

  $msg = $installed_bundleset->formtable();
  $me->{'log'}->debug($msg);

#Complain about older versions

  if (@{$installed_bundleset->{'conflicts'}}) {
    $me->{'error_msg'} = "ERROR: The following bundles cannot be installed\n";

    for my $p (@{$installed_bundleset->{'conflicts'}}) {

      my ($old, $new);
      $old = "$p->{'replacer'}->{'Name'} ver: " . 
        $p->{'replacer'}->version_label();
      $new = "$p->{'replacee'}->{'Name'} ver: " . 
        $p->{'replacee'}->version_label();
      $me->{'error_msg'} .=  "\t$old is incompatible installed $new\n"; 
    }
    return undef;
  }

  my @replacements = map { $_->{'replacer'} } 
    @{$installed_bundleset->{'replacements'}};

  my @removed_bundles = map { $_->{'replacee'} } 
    @{$installed_bundleset->{'replacements'}};

  my @untouched_bundles =
    @{ $installed_bundleset->{'untouched'}};

  my @added_bundles =
    @{ $installed_bundleset->{'added'}};

  return {replace => \@replacements, 
          remove => \@removed_bundles, 
          untouched => \@untouched_bundles, 
          add => \@added_bundles};
}

sub update_check_bundles2unaffiliated {
  my ($me, %args) = @_;

  my @new_pkgs = @{$args{'new_pkgs'}};
  my @remove_pkgs = @{$args{'remove_pkgs'}};


  my $installed_unaffiliated =
    new Grid::GPT::PkgDefsSet(
                              log => $me->{'log'},
                              force => $me->{'force'},
                             );

  for my $p (@{$me->{'pkginst'}->{'pkgs'}}) {

    my $matches = 
      $me->{'bndlinst'}->find_package(
                                      pkgname => $p->pkgname(),
                                      flavor => $p->flavor(),
                                      pkgtype => $p->pkgtype(),
                                      version => $p->{'depnode'}->{'Version'},
                                     );
    next if @$matches;

    $installed_unaffiliated->add_pkgnode(node =>$p) 
      if ! grep {
        $_->pkgname() eq $_->pkgname() and 
          $_->flavor() eq $_->flavor() and 
            $_->pkgtype() eq $_->pkgtype() and 
              $_->{'version'}->is_equal($p->{'depnode'}->{'Version'})
      } @remove_pkgs;

  }

  my $msg = "+++installed unaffiliated package set+++\n";
  $msg .= $installed_unaffiliated->formtable();
  $me->{'log'}->debug($msg);


  my $new_pkgset =
    new Grid::GPT::PkgDefsSet(
                              force => $me->{'force'},
                              log => $me->{'log'},
                             );

  for my $p (@new_pkgs) {
    $new_pkgset->add_package(pkgdef => $p);
  }

  $me->{'log'}->debug("compared +++installed unaffiliated pkgs to new bundles +++\n");
  $installed_unaffiliated->compare(replacements => $new_pkgset);

  $msg = $installed_unaffiliated->formtable();
  $me->{'log'}->debug($msg);

  if (@{$installed_unaffiliated->{'conflicts'}}) {
    $me->{'error_msg'} = "ERROR: The following package conflicts were found:\n";

    for my $c (@{$installed_unaffiliated->{'conflicts'}}) {
      my $old = $c->{'replacee'};
      my $new = $c->{'replacer'};

      $me->{'error_msg'} .=  "\t" . $new->label() . 
        " ver: " . $new->version_label() .
          " in bundle " . $new->{'bundle'}->label() . 
      " conflicts with " . $old->label() .
        " ver: " . $old->version_label() . "\n";
    }
    return undef;
  }

  if (@{$installed_unaffiliated->{'downgrades'}}) {
    my $msg= "WARNING: The following packages have updated versions already installed:\n";

    for my $c (@{$installed_unaffiliated->{'downgrades'}}) {
      my $old = $c->{'replacee'};
      my $new = $c->{'replacer'};

      $msg .=  "\t" . $new->label() . 
        " ver: " . $new->version_label() .
          " in bundle " . $new->{'bundle'}->label() . 
      " is older than " . $old->label() .
        " ver: " . $old->version_label() . "\n";
    }
    $me->{'log'}->inform($msg);
  }

  my @replaced_pkgs =
    @{$installed_unaffiliated->{'replaced'}};

  @new_pkgs =
    @{$installed_unaffiliated->{'added'}};
  push @new_pkgs, map { $_->{'replacer'} }
    @{$installed_unaffiliated->{'replacements'}};

  return { replaced_pkgs => \@replaced_pkgs, new_pkgs => \@new_pkgs};
}

sub update_new_pkg_consistency_check {
  my ($me, %args) = @_;
  my @new_pkgs = @{$args{'new_pkgs'}};

  $me->{'log'}->debug("+++ new pkg consistency check +++\n");

  my $set = new Grid::GPT::PkgDefsSet(
                                    force => $me->{'force'},
                                    log => $me->{'log'},
                                   );

  my @bad;
  for my $p (@new_pkgs) {
    my $loose = $p->{'bundle'} ne 'NONE' ? $p->{'bundle'}->is_old_style(): 0;
    my @sames = grep { $_->name() eq $p->name()} @{$set->{'pkgs'}};
    if (@sames) {
      my $results = $set->filter_replacement_pkgs(replacer => $p, 
                                                 loose => $loose,
                                                 candidates => \@sames);

      push @bad, grep { ! $_->{'replacer'}->is_same($_->{'replacee'}) }
        @{$results->{'replacements'}}, @{$results->{'conflicts'}};

      next if ! @{$results->{'added'}}; # $p is ignored.
    }
    $set->add_package(pkgdef => $p);
  }


  return $set->{'pkgs'} if ! @bad;

#Complain about pkg conflicts

  $me->{'error_msg'} = "ERROR: The following new packages conflict with each other:\n";
  
  for my $c (@bad) {
    my $old = $c->{'replacee'};
    my $new = $c->{'replacer'};

    $me->{'error_msg'} .=  "\t" . $new->label() . 
      " ver: " . $new->version_label() .
        " in bundle " . ($new->{'bundle'} ne 'NONE' ? 
	$new->{'bundle'}->label() : 'NONE') . 
          " conflicts with " . $old->label() .
            " ver: " . $old->version_label() .
        " in bundle " . ($old->{'bundle'} ne 'NONE' ? 
	$old->{'bundle'}->label() : 'NONE') . 
        "\n";
  }

  return undef;
}

sub update_check_bundles2pkgs {
  my ($me, %args) = @_;
  my @untouched_bundles = @{$args{'untouched'}};
  my @remove_bundles = @{$args{'remove'}};
  my @new_bundles = (
                     @{$args{'replace'}}, 
                     @{$args{'add'}},
                    );

  my @remove_pkgs = map { ( @{$_->{'PkgDefs'}->{'pkgs'}} )} 
    @remove_bundles;


  my $installed_pkgs = new Grid::GPT::PkgDefsSet(
                                                 force => $me->{'force'},
                                                 log => $me->{'log'},
                                                );
  my $new_pkgs = new Grid::GPT::PkgDefsSet(
                                           force => $me->{'force'},
                                           log => $me->{'log'},
                                          );

# Filter out remove bundles for the update check.
  for my $b (@{$me->{'bndlinst'}->{'bundles'}}) {
    next if grep { $_->is_same($b) } @remove_bundles;
    $installed_pkgs->add_bundle(bundle => $b);
  }

  my (@bad, @downgrades);

  for my $b (@new_bundles) {

    $me->{'log'}->debug("+++compared installed pkgs to bundle $b->{'Name'} +++");
    $installed_pkgs->compare(replacements => $b->{'PkgDefs'}, 
                             '2xbundle' => $b->is_old_style());

    my $msg = $installed_pkgs->formtable();
    $me->{'log'}->debug($msg);

    my $conflicts = $installed_pkgs->{'conflicts'};
    push @bad, @$conflicts if @$conflicts;

    push @bad, 
      grep { ! $_->{'replacer'}->is_same($_->{'replacee'})} 
        @{$installed_pkgs->{'replacements'}} 
          if @{$installed_pkgs->{'replacements'}} and ! defined $me->{'force'};

    next if @$conflicts;

    push @downgrades, @{$installed_pkgs->{'downgrades'}};

    my @additional_pkgs = map { $_->{'replacer'} } 
      @{$installed_pkgs->{'replacements'}};

    push @additional_pkgs,
      @{$installed_pkgs->{'added'}};

    push @remove_pkgs, 
      @{$installed_pkgs->{'replaced'}};

    for my $p (@additional_pkgs) {
      $new_pkgs->add_package(pkgdef => $p);
    }

    $installed_pkgs->add_bundle(bundle => $b);

  }

#Complain about bundle conflicts

  if (@bad) {
    $me->{'error_msg'} = "ERROR: The following package conflicts were found:\n";

    for my $c (@bad) {
      my $old = $c->{'replacee'};
      my $new = $c->{'replacer'};

      $me->{'error_msg'} .=  "\t" . $new->label() . 
        " ver: " . $new->version_label() .
        " in bundle " . $new->{'bundle'}->label . 
          " conflicts with " . $old->label() .
          " ver: " . $old->version_label() .
            " in bundle " . $old->{'bundle'}->label() . "\n";
    }
    return undef;
  }

  if (@downgrades) {
    my $msg= "WARNING: The following packages have updated versions already installed:\n";

    for my $c (@downgrades) {
      my $old = $c->{'replacee'};
      my $new = $c->{'replacer'};

      $msg .=  "\t" . $new->label() . 
        " ver: " . $new->version_label() .
          " in bundle " . $new->{'bundle'}->label() . 
      " is older than " . $old->label() .
        " ver: " . $old->version_label() . "\n";
    }
    $me->{'log'}->inform($msg);
  }

  $me->dump_results(
                    new_bundles => \@new_bundles,
                    removed_bundles => \@remove_bundles,
                    new_packages => $new_pkgs->{'pkgs'},
                    removed_packages => \@remove_pkgs,
                   );


  # Check if unaffiliated packges conflict with the bundles

    $me->{'log'}->debug("+++compared installed pkgs to unaffiliated pkgs+++\n");
  $installed_pkgs->compare(replacements =>  $args{'pkgs'});

    my $msg = $installed_pkgs->formtable();
    $me->{'log'}->debug($msg);

  if (@{$installed_pkgs->{'conflicts'}}) {
    $me->{'error_msg'} = "ERROR: The following package conflicts were found:\n";

    for my $c (@{$installed_pkgs->{'conflicts'}}) {
      my $old = $c->{'replacee'};
      my $new = $c->{'replacer'};

      $me->{'error_msg'} .=  "\t" . $new->label() . 
        " ver: " . $new->version_label() .
        " conflicts with " . $old->label() .
          " ver: " . $old->version_label() .
            " in bundle " . $old->{'bundle'}->label() . "\n";
    }
    return undef;
  }

  my @additional_pkgs = map { $_->{'replacer'} } 
      @{$installed_pkgs->{'replacements'}};

  push @additional_pkgs, 
    @{$installed_pkgs->{'added'}};

  push @remove_pkgs, 
    @{$installed_pkgs->{'replaced'}};

  my @force_remove_pkgs =
    @{$installed_pkgs->{'replaced'}};

  for my $p (@additional_pkgs) {
    $new_pkgs->add_package(pkgdef => $p);
  }


  return { 
          new_pkgs => $new_pkgs->{'pkgs'},
          remove_pkgs => \@remove_pkgs,
          force_remove_pkgs => \@force_remove_pkgs,
         };
}

sub update_file_conflict_check {
  my ($me, %args) = @_;
  my ($new_pkgs, $remove_pkgs) = ($args{'new_pkgs'}, $args{'remove_pkgs'});

  my $new_installation =  new Grid::GPT::PkgSet(
                                                with_filelists => 1,
                                                with_masterfilelist => 1,
                                               );

  for my $p (@{$me->{pkginst}->{'pkgs'}}) {
    next if grep { $p->is_same($_) } @$remove_pkgs;

    $new_installation->add_package( pkgnode => $p );
  }

  $new_installation->resetMasterFilelist();

  my @bad;

  for my $p (@$new_pkgs) {

    next if ! defined $p->filelist(); # rpm's do not have filelists.

    my $fileconflicts = $new_installation->check_files($p);
    if ( @$fileconflicts )
    {
      push @bad, { pkg => $p, conflicts => $fileconflicts};
    }
  }

  if (@bad) {
    $me->{'error_msg'} = "Error: The following file conflicts were found:\n";

    for my $c (@bad) {
      my $pkg = $c->{'pkg'};
      my $conflicts = $c->{'conflicts'};

      $me->{'error_msg'} .= "Package ".($pkg->label()). " has file conflicts with the following:\n";
      for my $i (@$conflicts) {
        $me->{'error_msg'}  .= "   $i->{'file'} owned by ".($i->{'pkgnode'}->label())."\n";
      }
    }
    return "FOUND_CONFLICTS";
  }

  return "PASSED";

}

sub _2xbundle2obj {
  my ($me, %args) = @_;
  my @to_install_2x_bundle_objects;

  for my $b (@{$args{'2xbundles'}}) {
    my $bundle = 
      new Grid::GPT::V1::Bundle(
                                tmpdir => $me->{'locations'}->{'tmpdir'},
                                log => $me->{'log'},
                                force => $me->{'force'},
                               );

    $bundle->read_bundle_from_tar(file => $b);

    if (! defined $me->{'force'}) {

      if ( grep { $_->label() eq $bundle->label() } @{$me->{'bndlinst'}->{'bundles'}}) {
        $me->{'log'}->inform("Bundle " . $bundle->label() . " already installed");
        next;
      }
    }
    $bundle->create_pkgdefs_set();
    push @to_install_2x_bundle_objects, $bundle;
  }

  return \@to_install_2x_bundle_objects;

}

sub remove {
  my ($me, %args) = @_;

  # Get list of uninstall bundles or packages

  my (@uninstall_bundles,  @bad, @pkg_inputs);
  my $uninstall_pkgs= new Grid::GPT::PkgSet(
                                            log => $me->{'log'},
                                            force => $me->{'force'},
                                           );
  
  my $input_bundles = $args{'inputs'};

  if (defined $args{'bundles'}) {
    for my $i (@$input_bundles) {

      my $bundle = $me->{'bndlinst'}->find_bundle(bundle => $i);

      if (! defined $bundle) {
        push @bad, $i;
        next
      }

      push @uninstall_bundles, $bundle;

      my $list = $bundle->getFullBundleIncludedPackageList();

      # We really need some consistent naming here :(
      push @pkg_inputs, map {{
        pkgname =>$_->{'Name'}, 
          flavor =>$_->{'Flavor'}, 
            pkgtype =>$_->{'Type'}
          }} @$list;
      next;
    }

    if (@bad) {
      $me->{'error_msg'} = 
        "ERROR: The following does not match any bundles:\n";
      for my $b (@bad) {
        $me->{'error_msg'} .= "\t$b\n";
      }
      return undef;
    }
  } else {
    push @pkg_inputs, @{ $me->sort_input_patterns(inputs => $args{'inputs'}) };
  }

  for my $p (@pkg_inputs) {

    my $pkgs = $me->{'pkginst'}->query(%$p);

    # Complain about pattern if it does not come from a bundle.
    if (! defined $pkgs and ! defined $args{'bundles'}) {
      my $input = "$p->{'pkgname'}-$p->{'flavor'}-$p->{'pkgtype'}";

      $input =~ s!ANY!*!;

      push @bad, $input;
      next;
    }

    my $msg = "REMOVE: Query: /pkgname=$p->{'pkgname'}/flavor=$p->{'flavor'}/pkgtype=$p->{'pkgtype'} finds these pkgs:\n";

    for my $pk (@$pkgs) {
      $msg .= "\t" . $pk->label() . "\n";
      $uninstall_pkgs->add_package(pkgnode => $pk)
    }

    $me->{'log'}->debug($msg);

  }

  if (@bad) {
    $me->{'error_msg'} = "ERROR: The following does not match any packages:\n";
    for my $b (@bad) {
      $me->{'error_msg'} .= 
        "\t$b->{'pkgname'}-$b->{'flavor'}-$b->{'pkgtype'}\n";
    }
    return undef;
  }

# Return now if -force flag is set.

    return { bndls => \@uninstall_bundles, pkgs => $uninstall_pkgs->pkgs() } 
      if defined $me->{'force'};


    $me->filter_remove_pkgs( 
                            bndls => \@uninstall_bundles, 
                            pkgs => $uninstall_pkgs);

    return { bndls => \@uninstall_bundles, pkgs => $uninstall_pkgs->pkgs() };

}

sub filter_remove_pkgs {
  my ($me, %args) = @_;

  my ($uninstall_pkgs, $force_uninstall_pkgs, $uninstall_bundles) = 
    ($args{'pkgs'}, $args{'force_pkgs'}, $args{'bndls'});
  # Check to see if any uninstall packages are owned by any other bundles

  my @dependent_bundles;

  $force_uninstall_pkgs = [] if ! defined $force_uninstall_pkgs;

  for my $p (@{$uninstall_pkgs->{'pkgs'}}) {

    next if grep { $p->is_same($_) } @$force_uninstall_pkgs;

    my $depbndls =   
      $me->{'bndlinst'}->find_package(
                                      pkgname => $p->pkgname(),
                                      flavor => $p->flavor(),
                                      pkgtype => $p->pkgtype(),
                                      version => $p->version(),
                                     );
    push @dependent_bundles, map { { pkg => $p, bndl_name => $_->{'Name'}} }
      @$depbndls;
  }

  my @reinstalled_pkgs;
  
  for my $db (@dependent_bundles) {
    if (! grep { $db->{'bndl_name'} eq $_->{'Name'} }
        @$uninstall_bundles) {
      push @reinstalled_pkgs, $db;
    }
  }


  if (@reinstalled_pkgs) {
    my $msg = "The following packages are owned by other installed bundles
and so will not be removed\n";
    
    for my $rp (@reinstalled_pkgs) {
      $msg .= "\t" . $rp->{'pkg'}->label() . " is needed by $rp->{'bndl_name'}\n";
      $uninstall_pkgs->remove_package(pkgnode =>$rp->{'pkg'});

    }
    
    $me->{'log'}->inform($msg);
  }
# Remove these packages from the uninstall list

  return $uninstall_pkgs if defined $args{'nodeps'};

# Check to see if any other packages depend on the uninstall packages

    my @dependent_pkgs;

    for my $p (@{$uninstall_pkgs->{'pkgs'}}) {
      my $depenv = ($p->pkgtype() eq 'dev') ? 'Build' 
                                          : 'Runtime';

      $me->{'pkginst'}->set_depenv($depenv, $p->flavor());

      my $list   = $p->query_provide_pkgs();
      my @prvs;

      for my $lp (@$list) {
        next if grep { $lp->is_same($_) } @{$uninstall_pkgs->{'pkgs'}};
        push @prvs, $lp;
      }
      push @dependent_pkgs, { pkg => $p, depends => \@prvs } if @prvs;
    }


# Prepare a report

  if (@dependent_pkgs) {
    my $msg = "The following packages fulfill dependencies to other installed \
packages and so will not be removed\n";

    for my $rp (@dependent_pkgs) {
      $msg .= "\t" . $rp->{'pkg'}->label() . " is needed by the following packages:\n";
      
      for my $dp (@{$rp->{'depends'}}) {
        $msg .= "\t\t" . $dp->label() . "\n";
      }

      $uninstall_pkgs->remove_package(pkgnode =>$rp->{'pkg'});
    }
    $me->{'log'}->inform($msg);
  }

}


sub sort_input_patterns {
  my ($me, %args) = @_;

  my @queries;


  for my $i(@{$args{'inputs'}}) {
    my $q =  $me->{'namematch'}->parse_name($i);
    push @queries, $q;
    $me->{'log'}->debug("Pattern: " . $i .
                        " => /pkgname=$q->{'pkgname'}/flavor=$q->{'flavor'}/pkgtype=$q->{'pkgtype'}");
  }

  return \@queries
}

sub sort_input_files {
  my ($me, %args) = @_;

  my %sorted_inputs =(
                      native_pkgs => [],
                      bin_pkgs => [],
                      src_pkgs => [],
                      native_bundles => [],
                      native_2xbundles => [],
                      bin_bundles => [],
                      bin_2xbundles => [],
                      src_bundles => [],
                      src_2xbundles => [],
                      bad => [],
                     );

  for my $i (@{$args{'inputs'}}) {
    my $file = Grid::GPT::FilelistFunctions::abspath($i);
    my $check = check_input_file(file => $file);
    push @{$sorted_inputs{'bad'}}, { file => $file, reason => $check } 
      if $check eq 'FILE_DOES_NOT_EXIST' or
        $check eq 'FILE_UNREADABLE' or 
          $check eq 'NOT_A_GPT_FILE';
    push @{$sorted_inputs{'native_pkgs'}}, $file if $check eq 'NATIVE_PKG';
    push @{$sorted_inputs{'bin_pkgs'}}, $file if $check eq 'BIN_PKG';
    push @{$sorted_inputs{'src_pkgs'}}, $file if $check eq 'SRC_PKG';
    push @{$sorted_inputs{'native_bundles'}}, $file if $check eq 'NATIVE_BUNDLE';
    push @{$sorted_inputs{'bin_bundles'}}, $file if $check eq 'BIN_BUNDLE';
    push @{$sorted_inputs{'src_bundles'}}, $file if $check eq 'SRC_BUNDLE';
    push @{$sorted_inputs{'native_2xbundles'}}, $file 
      if $check eq 'NATIVE_2xBUNDLE';
    push @{$sorted_inputs{'bin_2xbundles'}}, $file if $check eq 'BIN_2xBUNDLE';
    push @{$sorted_inputs{'src_2xbundles'}}, $file if $check eq 'SRC_2xBUNDLE';
  }


  my %reasonstring = ('FILE_DOES_NOT_EXIST' => " does not exist", 
                      'FILE_UNREADABLE' => " cannot be read", 
                      'NOT_A_GPT_FILE' => " is not a GPT file");

  if (@{$sorted_inputs{'bad'}}) {
    $me->{'error_msg'} = "ERROR: The following files are invalid:\n";
    for my $f (@{$sorted_inputs{'bad'}}) {
      $me->{'error_msg'} .= "\t$f->{'file'} $reasonstring{$f->{'reason'}}\n";
    }
    return undef;
  }

  if (defined $me->{'source'}) {

    my @badfiles = (
                    @{$sorted_inputs{'bin_bundles'}}, 
                    @{$sorted_inputs{'bin_2xbundles'}},
                    @{$sorted_inputs{'bin_pkgs'}},
                    @{$sorted_inputs{'native_bundles'}},
                    @{$sorted_inputs{'native_2xbundles'}},
                    @{$sorted_inputs{'native_pkgs'}},
                   );

    if (@badfiles) {
      $me->{'error_msg'} = "ERROR the following files cannot be built.\nPlease use " .
        "gpt-install for these:\n";
      for my $f (@badfiles) {
        $me->{'error_msg'} .= "\t$f\n";
      }
      return undef;
    }

    return { 
            bundles => $sorted_inputs{'src_bundles'},
            '2xbundles' => $sorted_inputs{'src_2xbundles'},
            pkgs =>$sorted_inputs{'src_pkgs'}
           };

  }

  my @badfiles = (
                  @{$sorted_inputs{'src_bundles'}}, 
                  @{$sorted_inputs{'src_2xbundles'}}, 
                  @{$sorted_inputs{'src_pkgs'}}
                 );
  if (@badfiles) {
    $me->{'error_msg'} = "ERROR the following files cannot be installed.\nPlease " . 
      "use gpt-build for these:\n";
    for my $f (@badfiles) 
      {
        $me->{'error_msg'} .= "\t$f\n";
      }
    return undef;
  }

  return { 
          bundles => 
          [
           @{$sorted_inputs{'bin_bundles'}},
           @{$sorted_inputs{'native_bundles'}}
          ],
          '2xbundles' => 
          [
           @{$sorted_inputs{'bin_2xbundles'}},
           @{$sorted_inputs{'native_2xbundles'}}
          ],

          pkgs => 
          [
           @{$sorted_inputs{'bin_pkgs'}},
           @{$sorted_inputs{'native_pkgs'}}
          ],
         };
}

sub dump_results 
  {
    my ($me, %results) = @_;

    my $msg = "Current Results:\n";


    for my $t('removed_bundles', 
              'new_bundles', 
              'removed_packages', 
              'force_removed_packages',
              'new_packages'
             ) {
    $results{$t} = [] if ! defined $results{$t};
    }

    $msg .=  "The following bundles would be removed\n" if @{$results{'removed_bundles'}};

    for my $b (@{$results{'removed_bundles'}}) {
      $msg .=  "\t$b->{'Name'} ver: " . $b->version_label() . "\n";
    }

    $msg .=  "The following bundles would be installed\n" if @{$results{'new_bundles'}};

    for my $b (@{$results{'new_bundles'}}) {
      $msg .=  "\t$b->{'Name'} ver: " . $b->version_label() . "\n";
    }

    $msg .=  "The following packages would be removed\n" if @{$results{'removed_packages'}};

    for my $p (@{$results{'removed_packages'}}) {
      $msg .=  "\t" .$p->label() ." ver: " . 
        $p->version_label() . "\n";
    }
    
    $msg .=  "The following packages would be forcefully removed\n" if @{$results{'force_removed_packages'}};
    
    for my $p (@{$results{'force_removed_packages'}}) {
      $msg .=  "\t" .$p->label() ." ver: " . 
        $p->version_label() . "\n";
    }

    $msg .=  "The following packages would be installed\n" if @{$results{'new_packages'}};

    for my $p (@{$results{'new_packages'}}) {
      $msg .=  "\t" .$p->label() ." ver: " . 
        $p->version_label() . "\n";
    }

    $me->{'log'}->debug($msg);

}


sub error_msg {
  my ($me) = @_;

  $me->{'log'}->error($me->{'error_msg'});
}

sub check_input_file {
  my (%args) = @_;
  
  my $file = $args{'file'};

  return "FILE_DOES_NOT_EXIST" if ! -f $file;

  my $tar = Archive::Tar->new();

  $file = Grid::GPT::FilelistFunctions::abspath($file);

  return "NATIVE_PKG" if $file =~ m!\.rpm$!;

  return "FILE_UNREADABLE" if -T $file; # Testing if $file is text.

  return "NATIVE_PKG" if $file =~ m!\.rpm$!;

  my $ret = $tar->read($file);
  return "FILE_UNREADABLE" if !defined( $ret );

  my @contents = $tar->list_files();

  my $bundle_style = 'OLD';

  $bundle_style = 'NEW' if grep { /\.gpt-bundle\.xml/ } @contents;

  if (grep { $_ eq "packagelist" } @contents) {
    if (grep { m!\.rpm$! } @contents) {
      return "NATIVE_BUNDLE" if $bundle_style eq 'NEW';
      return "NATIVE_2xBUNDLE";
    }
    return "BIN_BUNDLE" if $bundle_style eq 'NEW';
    return "BIN_2xBUNDLE";
  }

  if (grep { $_ eq "packaging_list"} @contents) {
    return "SRC_BUNDLE" if $bundle_style eq 'NEW';
    return "SRC_2xBUNDLE";
  }

  return "BIN_PKG" if grep { m!etc/gpt/packages! } @contents;
  return "BIN_PKG" if grep { m!etc/globus_packages! } @contents;
##  return "BIN_PKG" if grep { m!etc/gpt/packages! } @contents;
  return "SRC_PKG" if grep { m!pkgdata! } @contents;
  return "SRC_PKG" if grep { m!pkg_data_src.gpt! } @contents;

  return "NOT_A_GPT_FILE";

}


sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
