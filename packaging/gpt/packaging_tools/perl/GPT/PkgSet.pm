package Grid::GPT::PkgSet;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

require Grid::GPT::PkgNode;
use Data::Dumper;
require Grid::GPT::BaseTable;
require Grid::GPT::PkgMngmt::Inform;
require Grid::GPT::GPTFilelist;
require Grid::GPT::PackageFilelist;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseTable);
sub _init {
  my ($me, %args)  = @_;
  $me->{'missing'} = [];
  $me->{'duplicates'} = [];
  $me->{'pkgs'} = [];
  $me->{'sorted'} = [];
  $me->{'exclusions'} = [];
  $me->{'exclude_setups'} = undef;
  $me->{'log'} = defined $args{'log'} ? $args{'log'} :
    new Grid::GPT::PkgMngmt::Inform;
  $me->{'indexes'} = ['pkgname','flavor','pkgtype', 'setupname'];

    my $mf = $args{'with_masterfilelist'};
    if (!defined($mf))
    {
        $mf = 1;
    }
    $me->{'with_masterfilelist'} = $mf;

    if ($mf)
    {
        #
        # create a masterFilelist to track all of the files in our package set
        #

        my $masterFilelist = new Grid::GPT::GPTFilelist( );
        if (!defined($masterFilelist))
        {
            die("ERROR: master filelist object is undefined");
        }
        $me->{'masterFilelist'} = $masterFilelist;
    }
}

sub cleardepenv {
  my ($me) = @_;

  for my $p (@{$me->{'pkgs'}}) {
    $p->clearmatches;
  }
  $me->{'missing'} = [];
  $me->{'duplicates'} = [];
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

sub add_package {
  my ($me, %arg) = @_;

  my $object = $arg{'pkgnode'};
  $object = new Grid::GPT::PkgNode(depnode => $arg{'pkg'},
				   flavor => $arg{'flavor'},
				   log => $me->{'log'},
				  )
    if ! defined $object;

  my $exists = $me->get_package(pkgnode => $object);
  if (defined $exists) {

    return $exists if $object->pkgtype() eq 'src';;

# We need to manage this warning better. It annoys users.

#    print "WARNING: PkgSet: package ";
#    $object->printnode();
#    print "Is a duplicate of ";
#      $exists->printnode();
    return $exists;
  }

  $me->add_object(depnode => $object,
                  pkgname => $object->pkgname(),
                  flavor => $object->flavor(),
                  setupname => $object->setupname(),
                  pkgtype => $object->pkgtype(),
                  );

  $me->{'log'}->debug("PKGSET: Adding Pkg : ". $object->label()) 
    if defined $me->{'log'};

  push @{$me->{'pkgs'}}, $object;

  # new package forces a new sort
  $me->{'sorted'} = [];


    if ( $arg{'with_filelists'} and !$arg{'no_package_filelist'} )
    {
        my $fileset = new Grid::GPT::PackageFilelist(
                            context => $arg{'context'},
                            contextData => $arg{'contextData'},
                            pkgnode => $object,
                            masterFilelist => $me->masterFilelist,
                            convert => $arg{'convert'},
                            );

        if ( !defined($fileset) )
        {
            die("ERROR: package filelist object is undefined");
        }

        my $retval = $fileset->open();

        if ( !$fileset->isEmpty() ) {
          $object->add_filelist($fileset);
        } else {
#          print "WARNING: Package ", $object->label(), " has no filelist\n";
        }
    }

  return $object;
}

sub remove_package {
  my ($me, %arg) = @_;

  my $object = $arg{'pkgnode'};
  my $exists = $me->get_package(pkgnode => $object);
  return if (! defined $exists);

  $me->Grid::GPT::BaseTable::remove_package( depnode   => $object,
                                             pkgname   => $object->pkgname(),
                                             flavor    => $object->flavor(),
                                             setupname => $object->setupname(),
                                             pkgtype   => $object->pkgtype(),
                                           );

  my @newlist = grep { ! $object->is_same($_) } @{$me->{'pkgs'}};

  $me->{'pkgs'} = \@newlist;
  $me->{'sorted'} = [];

#  $me->printtable();
}

sub resetMasterFilelist
{
    my $self = shift;

    my $mf = $self->{'masterFilelist'};
    my $pkgList = $self->query();

    if (defined($mf))
    {
        $mf->reset();
    }

    for my $pkg (@$pkgList)
    {
        $pkg->setMasterFilelist(mf => $mf);
        $pkg->addToMasterFilelist();
    }
}

### saveFilelist( )
#
# for every node in our set of packages, save it's filelist entry
#

sub saveFilelist
{
    my $self = shift;

    my $nodeList = $self->query();

    for my $node (@$nodeList)
    {
        $node->filelist()->save();
    }
}

sub check_files
{
    my ($me, $node) = @_;

    my @conflicts;
    my $conflictList = $me->{'masterFilelist'}->getPackageConflicts(node => $node);

    if ( scalar(@$conflictList) > 0 )
    {
        for my $f (@$conflictList)
        {
            push(@conflicts, { file => $f->getPath(), pkgnode => $f->getPkgNode() } );
        }
    }

    return \@conflicts;
}

sub find_file
{
    my $self = shift;
    my($name) = @_;

    return $self->{'masterFilelist'}->translatePathToPkgNode( path => $name );
}

sub removeFilePath
{
    my $self = shift;
    my(%args) = @_;

    my $path = $args{'path'};

    $self->{'masterFilelist'}->removeFilePath( path => $path );
}

sub get_package {
  my ($me, %args) = @_;
  my ($pkgname, 
      $flavor, 
      $pkgtype, 
      $setupname) = ($args{'pkgname'} || 'ANY', 
                     $args{'flavor'} || 'ANY',
                     $args{'pkgtype'} || 'ANY',
                     $args{'setupname'} || 'ANY');

  if (defined $args{'pkgnode'}) {
    my @pkgs = grep {$_->is_same($args{'pkgnode'}) } @{$me->{'pkgs'}};
    return $pkgs[0];
  }
    

  return undef if ! defined $me->{'table'}->{$pkgname};
  return undef 
    if ! defined $me->{'table'}->{$pkgname}->{$flavor};  
  return undef 
    if ! defined $me->{'table'}->{$pkgname}->{$flavor}->{$pkgtype};  
  return  
    $me->{'table'}->{$pkgname}->{$flavor}->{$pkgtype}->{$setupname};
}

sub set_depenv {
  my ($me, $depenv, $flavor) = @_;

  $me->{'log'}->debug("PKGSET: Setting DepEnv to : ". $depenv . 
                      " flavor: " . (defined $flavor ? $flavor : 'N/A')) 
    if defined $me->{'log'};

#  map { $_->printnode() } @{$me->{'pkgs'}};

  for my $p(@{$me->{'pkgs'}}) {
    $p->match_pkg_deps(depenv =>$depenv, 
                       table=>$me,
                       flavor => $flavor,
                       missing => sub {$me->add_to_missing(@_); },
                       duplicates => sub {$me->add_to_duplicates(@_); },
                      );

  }

  $me->{'log'}->debug("PKGSET: Resulting Table: \n" . $me->formtable(full=>1))
    if defined $me->{'log'};

  # new dependency environment forces a new sort
  $me->{'sorted'} = [];
}



sub add_to_missing {
  my ($me, %args) = @_;

  my $missme = $args{'missing'}->clone();
  $missme->{'flavor'} = $args{'flavor'};
  $missme->{'pkgtype'} = $args{'pkgtype'};

  return if grep { $_->{'pkg'}->is_same($args{'pkg'}) &&
                     $_->{'needs'}->is_same($missme)
                   }
    @{$me->{'missing'}};

  my $pkgs = defined $args{'badversions'} ?  $args{'badversions'} : [];
  my $badversion;

  if (defined $me->{'log'}) {

    my $msg = "MATCH: Missing Dependency for  Package: ";

    $msg .= $args{'pkg'}->label();
    $msg .= "\nwith dep: " . $args{'missing'}->label(versions => 1);
    $msg .= "\nwith query adjustments:
\t/flavor=$args{'flavor'}/pkgtype=$args{'pkgtype'}\n";
    $msg .= "Candidates: \n";
    for my $p (@$pkgs) {
      $msg .= "\t" . $p->label(full=>1) . "\n";
    }
    $me->{'log'}->debug($msg); 
  }


  if (@$pkgs) {
    $badversion = $pkgs->[0]->{'version'}->label() if defined $pkgs->[0]->{'version'};
  }
  my $obj = {
             pkg => $args{'pkg'},
             needs => $missme,
             badversions => $args{'badversions'},
             version => $badversion,
            };

    push @{$me->{'missing'}}, $obj;
}

sub add_to_duplicates {
  my ($me, %args) = @_;

  my $obj = {
             pkg => $args{'pkg'},
             dep => $args{'dep'},
             dups => $args{'dups'},
            };

  if (defined $me->{'log'}) {

    my $msg = "MATCH: Duplicates found for package: ";

    $msg .= $args{'pkg'}->label();
    $msg .= "\nwith dep: " . $args{'dep'}->label(versions => 1);
    for my $p (@{$args{'dups'}}) {
      $msg .= "\t" . $p->label() . "\n";
    }
    $me->{'log'}->debug($msg); 
  }

    push @{$me->{'duplicates'}}, $obj;
}

sub query_provides {
  my ($me, %args) = @_;

  my $pkgnode = $args{'pkgnode'};

  # Passing in any of deptype, pkgname, flavor, or pkgtype
  return $pkgnode->query_provide_pkgs(%args);
}
sub simple_sort_pkgs {
  my ($me, %args) = @_;

    my @pkgs = sort { $a->pkgname() cmp $b->pkgname() ||
                            $a->flavor() cmp $b->flavor() ||
                              $a->pkgtype() cmp $b->pkgtype() } 
      @{$me->{'pkgs'}};

  $me->{'sorted'} = \@pkgs;
}

sub sort_pkgs {
  my ($me, %args) = @_;

  $me->{'sorted'} = [] if defined $args{'force'};

  return $me->{'sorted'} if @{$me->{'sorted'}};


  # initialize the dependency counters
  for my $p (@{$me->{'pkgs'}}) {
    $p->init_matches();
  }

  my @pkgs = @{$me->{'pkgs'}};

  # Variable to track for circular dependencies which will cause an infinite loop.
  my $infinite_loopcheck = 0;

  if (defined $me->{'log'}) {

    my $msg = "SORT: Unsorted Packages: \n";
    
    for my $p (@pkgs) {
      $msg .= "\t" . $p->label() . "\n";
    }

    $me->{'log'}->debug($msg); 
  }
  while (@pkgs) {
    
    if (defined $me->{'log'}) {

      my $msg = "SORT: Remaining Packages: \n";
    
      for my $p (@pkgs) {
        $msg .= "\t" . $p->label() . "\n";
        $msg .= $p->formmatches() . "\n";
      }

      $me->{'log'}->debug($msg); 
    }

    # Get all packages with no dependencies
    my @zerodeps = sort { $a->pkgname() cmp $b->pkgname() ||
                            $a->flavor() cmp $b->flavor() ||
                              $a->pkgtype() cmp $b->pkgtype() } 
      grep { $_->matchcount() == 0 } @pkgs;
    
    @pkgs = grep { $_->matchcount() != 0 } @pkgs;

    # remove the matches of all of the packages depending on the zerodep packages.
    for my $p(@zerodeps) {
      my $provs = $p->query_provide_pkgs();

      for my $prv (@$provs) {

        $prv->remove_matches($p);

      }
    }

    push @{$me->{'sorted'}}, @zerodeps;
    
    $infinite_loopcheck++ if ! @zerodeps;
    
    if ($infinite_loopcheck > 20) {
      # Die if an ininite loop is detected.
      
      select STDERR;
      print "ERROR: PkgSet: Circular Dependency Detected\n";
      print "Remaining Packages\n";
      for (@pkgs) {
        print "Package: ", $_->label(), " Count: ",$_->count_matched_pkgs(),"\n";
        $_->printmatches(full =>1);
      }
      die "Condition most likely in the packages with a count of 1\n";
    }
  }
}

sub extract_deptree {
  my ($me, %args) = @_;

  my $node = $me->get_package(pkgnode => $args{'srcpkg'});

  return undef if ! defined $node;

  my $pkgs = $node->query_dep_pkgs(deptype => $args{'srcdep'},
                                   flavor => $args{'flavor'});



  push @$pkgs, $node;

  return $me->extract_pkgset(pkgs =>$pkgs);


}

sub query_pkgset {
  my ($me, %args) = @_;

  my $pkgs;

  for my $n(@{$args{'pkgnames'}}) {
    my $qpkgs = $me->query(pkgname => $n, 
                           flavor => $args{'flavor'}, 
                           pkgtype => $args{'pkgtype'},
                          );
    push @$pkgs, @$qpkgs;
  }

  return $me->extract_pkgset(pkgs => $pkgs, deptype => $args{'deptype'});

}


sub extract_pkgset {
  my ($me, %args) = @_;
  my ($pkgs, $deptype, $preferred_flavor) = ($args{'pkgs'}, 
                                             defined $args{'deptype'} 
                                             ? $args{'deptype'} : 'ANY',
                                             $args{'preferred_flavor'},
                                            );

  my $pkgset = new Grid::GPT::PkgSet;

  for my $p (@$pkgs) {
    $me->_recurse_extract(pkg => $p, 
                          pkgset => $pkgset, 
                          deptype => $deptype,
                          preferred_flavor => $preferred_flavor
                         );
  }
 # print "Orignal:\n";
 # $me->printtable();
  @{$pkgset->{'missing'}} = 
    grep { defined $pkgset->get_package(pkgnode =>$_->{'pkg'}) } 
    @{$me->{'missing'}};

  @{$pkgset->{'sorted'}} = grep { defined $pkgset->get_package(pkgnode => $_) } 
    @{$me->{'sorted'}};


  $me->{'log'}->debug("EXTRACT: Extracted Set:\n" . $pkgset->formtable()) 
    if defined $me->{'log'};

  return $pkgset;

}

sub add_exclusion {
  my ($me, %args) = @_;

  push @{$me->{'exclusions'}}, $args{'query'};

}
sub exclude_setups {
  my ($me) = @_;

  $me->{'exclude_setups'} = 1;

}

sub clear_exclusions {
  my ($me, %args) = @_;

  $me->{'exclusions'} = [];
}

sub should_exclude {
  my ($me, %args) = @_;
  my $p = $args{'pkg'};

  if (defined $me->{'exclude_setups'} and $p->pkgname() =~ m!setup!) {
    $me->{'log'}->debug("EXTRACT: Excluding Setup Pkg : ". $p->label()) 
      if defined $me->{'log'};
    return 1;
  }

  if ( grep 
       { 
         ($_->{'flavor'} eq $p->flavor() or $_->{'flavor'} eq 'ANY') and
           ($_->{'pkgname'} eq $p->pkgname() or $_->{'pkgname'} eq 'ANY') and
             ($_->{'pkgtype'} eq $p->pkgtype() or $_->{'pkgtype'} eq 'ANY')
           } @{$me->{'exclusions'}}
     ) {
    $me->{'log'}->debug("EXTRACT: Excluding Pkg : ". $p->label()) 
      if defined $me->{'log'};
    return 1;
  }
  return 0;
}

sub _recurse_extract {
  my ($me, %args) = @_;
  my ($pkg, $pkgset, $preferred_flavor) = ($args{'pkg'}, 
                                           $args{'pkgset'},
                                           $args{'preferred_flavor'},
                                          );

  # Not sure why this is needed, perhaps some recursion quirk

  $me->{'log'}->debug("EXTRACT: Checking Pkg : ". $pkg->label()) 
    if defined $me->{'log'};

  return if defined $pkgset->get_package(pkgnode => $pkg);

  return if $me->should_exclude(pkg => $pkg);

  $me->{'log'}->debug("EXTRACT: Adding Pkg : ". $pkg->label()) 
    if defined $me->{'log'};

  $pkgset->add_package(pkgnode => $pkg);

  $preferred_flavor = $pkg->flavor if ! defined $preferred_flavor;

  my $pkgs = $pkg->query_dep_pkgs(deptype => $args{'deptype'},
                                  preferred_flavor => $preferred_flavor);

  my $msg = "EXTRACT: Dependent Pkgs: \n";
  
  for my $p (@$pkgs) {
    $msg .= "\t" . $p->label() . "\n";
  }

  $me->{'log'}->debug($msg); 

  for my $p (@$pkgs) {

  $me->{'log'}->debug("EXTRACT: Checking Pkg : ". $p->label()) 
    if defined $me->{'log'};

    next if defined $pkgset->get_package(pkgnode => $p);

  $me->{'log'}->debug("EXTRACT: Recursing Pkg : ". $p->label()) 
    if defined $me->{'log'};

    $me->_recurse_extract(pkg => $p, 
                          pkgset => $pkgset, 
                          deptype => $args{'deptype'},
                          preferred_flavor => $preferred_flavor,
                         );
  }
}

sub get_sorted_buildenvs {
  my ($me) = @_;

  $me->sort_pkgs();
#  $me->printtable(full=>1);
  my @libs;
  for my $p(@{$me->{'sorted'}}) {
    next if $p->pkgtype() ne 'dev'; # dev pkgs are the only installed pkgs containing build info.
    push @libs, $p->get_buildenv();
  }
  return \@libs;
}

sub check_missing {
  my ($me, %args) = @_;
  my ($rc);
  my $missing = $me->missing();
  if (@$missing) {
    if (defined $args{'log'}) {
      $ {$args{'log'}} = "ERROR: The following packages are missing\n";
    } else {
      select STDERR;
      print "ERROR: The following packages are missing\n";
    }
    $rc = $me->printmissing($args{'log'});
    if ($args{'die'} && $rc)
    {
      exit 1;
    }
    return 1;
  }
  return 0;
}

sub printtable {
  my ($me, %args) = @_;

  $me->Grid::GPT::BaseTable::printtable(%args);

  $me->printmissing();
}

sub formtable {
  my ($me,%args) = @_;

  my $msg = "";
  $msg .= $me->Grid::GPT::BaseTable::formtable(%args);

  $me->printmissing(\$msg);
  return $msg;
}

sub printtablehtml {
  my ($me, %args) = @_;

  my @pkgs = sort { $a->pkgname() cmp $b->pkgname() ||
                            $a->flavor() cmp $b->flavor() ||
                              $a->pkgtype() cmp $b->pkgtype() } 
    @{$me->{'pkgs'}};
  print "<h2> Packages:</h2>\n <ul>\n";
  for my $p (@pkgs) {
    print "<li>";
    $p->printnodehtml(href => 1);
    print "</li>\n";
  }
  print "</ul>\n";

  print "<h2> Missing Packages:</h2>\n";

  for my $m (@{$me->{'missing'}}) {
    my ($pkg, $needs, $version, $dep) = ($m->{'pkg'}->label(href=>1),
                                         $m->{'needs'}->label(),
                                         $m->{'version'},
                                         $m->{'needs'},
                                        );
    if (defined $version) {
        print "The following packages are incompatible with $pkg <br><ul>\n";
        for my $p (@{$m->{'badversions'}}) {
          print "<li>", $p->label(href=>1), " version ";
          print $p->{'depnode'}->version_label(), "</li>\n";
        }
        print "</ul>\n";
    } else {
        print "Package $pkg is missing $needs<br>\n";
      }
    print "Unfulfilled dependency is ", $dep->label(versions=>1), "<br><br>\n";

  }

  for my $p (@pkgs) {
    $p->printnodehtml();
  }
}

sub printmissing {
  my ($me, $log) = @_;
  my $result;

  for my $m (@{$me->{'missing'}}) {
    my ($pkg, $needs, $version) = ($m->{'pkg'}->label(),
                                   $m->{'needs'}->label(),
                                  $m->{'version'});
    if (defined $version) {
      if (defined $log) {
        $$log .= "Package $needs version $version is incompatible with $pkg\n";
      } else {
        print "Package $needs version $version is incompatible with $pkg\n";
      }
      $result=1;
    } else {
      if (defined $log) {
        $$log .= "Package $pkg is missing $needs\n";
      } else {
        print "Package $pkg is missing $needs\n";
      }
      $result=1;
    }
  }
  return $result;
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
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::DepIndexes - Perl extension for indexing package dependency metadata

=head1 SYNOPSIS

  use Grid::GPT::DepIndexes;
  my $pkg = new Grid::GPT::DepIndexes;

  $pkg->read_metadata_file('src_metadata.xml');
  my $bin_pkg = $pkg->convert_metadata($type, $build_flavor);
  $bin_pkg->output_metadata_file("$ {type}_metadata.xml");

=head1 DESCRIPTION

I<Grid::GPT::DepIndexes> is used to encapsulate a single
dependency found in a source package.  These dependencies are passed
on to the binary packages that are created from the source.  The
dependencies are divided into the following types:

=over 4

=item   compile

Dependency occurs when the package is used for compiling.  Usually
caused by header files including headers from other packages.  Passed
on to hdr and dev package types

=item   pgm_link

Dependency occurs when the programs created by this package were
linked.  Passed on to the pgm and pgm_static package types.

=item   lib_link

Dependency occurs when libraries created by this package are linked.
Passed on to the rtl and dev package types.


=item   data_runtime

Dependency needed during runtime by the data package.

=item   doc_runtime

Dependency needed during runtime by the doc package.

=item   lib_runtime

Dependency needed during runtime by the rtl and dev packages.

=item   pgm_runtime

Dependency needed during runtime by the pgm and pgm_static packages.

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::DepIndexes> object.  The function has
the following named objects:

=over 4

=item versions

Reference to an array of L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> objects.

=item name

Name of the dependent package.

=item type

The type of dependency.

=item pkg_type

The binary package type of the dependent package.

=back

=item fulfills_dependency(name, version)

Returns a 1 if the arguments met the requirements of the
dependency. Returns a 0 if not.


=item convert(binary_package_type)

Converts the dependency to a
L<Grid::Grid::BinaryDependency|Grid::Grid::BinaryDependency> object.

=item create_dependency_hash

This is a class function which creates a hash of
I<Grid::GPT::DepIndexes> objects out of an
L<Grid::GPT::XML|Grid::GPT::XML> object.

=back




=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::BinaryDependency(1) Grid::GPT::XML(1) Grid::GPT::V1::Version(1).

=cut
