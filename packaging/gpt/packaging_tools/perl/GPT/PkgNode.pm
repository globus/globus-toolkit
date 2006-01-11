package Grid::GPT::PkgNode;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %binary_dependencies);
use Data::Dumper;
require Grid::GPT::BaseNode;
require Grid::GPT::DepIndexes;
require Grid::GPT::MatchNode;
use Grid::GPT::V1::Version;
use Grid::GPT::V1::BinaryDependency;
use Grid::GPT::V1::SourceDependency;

# set the version for version checking
$VERSION     = 0.01;

@ISA = qw(Exporter Grid::GPT::BaseNode);

my %depenv2deptypes = (
                       Setup => ['Setup'],
                       BuildStatic => ['Compile', 'Build_Link'],
                       Build => ['Compile', 'Build_Link', 'Runtime_Link'],
                       BuildandSetup => ['Compile', 
                                         'Build_Link', 
                                         'Runtime_Link', 
                                         'Setup'],
                       BuildStaticandSetup => ['Compile', 
                                         'Build_Link', 
                                         'Setup'],
                       RuntimeStatic => ['Runtime'],
                       Runtime => ['Runtime','Runtime_Link'],
                       RuntimeandSetup => ['Runtime','Runtime_Link', 'Setup'],
                       RuntimeStaticandSetup => ['Runtime','Setup'],
                      );

my %bin2srcdeptypes =  (
                    'Compile' => ['compile'],
                    'Runtime_Link' => ['pgm_link','lib_link'],
                    'Build_Link' => ['pgm_link','lib_link'],
                    'Runtime' => ['data_runtime',
                                  'doc_runtime',
                                  'lib_runtime',
                                  'pgm_runtime' ],
                    'Setup' => ['Setup'],
                      );

sub _init {
  my ($me, %args)  = @_;
  $me->{'setupname'} = undef;
  $me->{'setupversion'} = undef;
  $me->{'depindexes'} = undef;
  $me->{'filelist'} = undef;
  $me->{'gptpkgfile'} = undef;
  $me->{'format'} = undef;
  $me->{'pkgindexes'} = new Grid::GPT::DepIndexes;
  $me->{'provideindexes'} = new Grid::GPT::DepIndexes;
  $me->{'count'} = 0;
  $me->{'installed'} = $args{'installed'};
  $me->{'log'} = $args{'log'};

  $me->_v1pkg(%args) 
    if ref($args{'depnode'}) eq 'Grid::GPT::V1::Package';
}

sub is_same {
  my ($me, $other) = @_;

  my $result = $me->{'depnode'}->is_same($other->{'depnode'});
#  if ($result) {
#    print $me->label(), " is the same as ", $other->label(), "\n";
#  } else {
#    print $me->label(), " is different than ", $other->label(), "\n";
#  }

  return $result;
}

sub is_equivalent {
  my ($me, $other) = @_;

  return 1 if $me->{'depnode'}->is_same($other->{'depnode'});

  return 0 if $me->pkgtype() !~ m!pgm! 
    and $other->pkgtype() !~  m!pgm!;

  return 1;
}

sub is_newer {
  my ($me, $other) = @_;

  return $me->{'depnode'}->is_newer($other->{'depnode'});

}

sub _v1pkg {
  my ($me, %args)  = @_;
  my $obj = $args{'depnode'};
  $me->_add_deptype($args{'deptype'});
  $me->_add_pkgname($obj->Name());
  my $flavor = $obj->Package_Type() eq 'src' ? 'ANY' : $obj->Flavor();
  $flavor = defined $args{'flavor'} ? $args{'flavor'} : $flavor;

  $me->_add_flavor($flavor);
  $me->_add_pkgtype($obj->Package_Type());
  $me->{'version'} = $obj->Version();
  $me->{'setupversion'} = $obj->Setup_Version();
  $me->{'setupname'} = $obj->Setup_Name();
  $me->{'depindexes'} = 
    $obj->Package_Type() eq 'src' ? $obj->{'Source_Dependencies'} : 
      $obj->{'Binary_Dependencies'};

#  $me->printnode(full=>1);
}

sub clearmatches {
  my ($me) = @_;
  $me->{'pkgindexes'} = new Grid::GPT::DepIndexes;
  $me->{'provideindexes'} = new Grid::GPT::DepIndexes;
}

sub match_pkg_deps {
  my ($me, %args) = @_;
  my ($depenv, $table, $missing, $topflavor) = ($args{'depenv'}, 
                                             $args{'table'}, 
                                             $args{'missing'},
                                            $args{'flavor'});

  return if ! defined $me->{'depindexes'};

  $me->{'log'}->debug("MATCH: Matching Deps for Pkg : " . $me->formnode()) 
    if defined $me->{'log'};


  my @deptypes = @{$depenv2deptypes{$depenv}};

  if ($me->pkgtype() eq 'src') {
    my %srcdeps;
    for my $dt(@deptypes) {
      for my $sdt (@{$bin2srcdeptypes{$dt}}) {
        $srcdeps{$sdt}++;
      }
    }
    @deptypes = keys %srcdeps;
  }

  for my $dt (@deptypes) {
    my $deps = $me->{'depindexes'}->query(deptype => $dt);
    
    next if ! $deps;

    
    for my $d (@$deps) {
      $me->{'log'}->debug("MATCH: Matching Dep: " . $d->label() . 
                          " for package " . $me->label())
    if defined $me->{'log'};

# globus_core now built in to GPT.

      if ($d->pkgname() eq 'globus_core') {

        $me->{'log'}->debug("Skipping because name is globus_core: ". $d->label()); 
        next;
      }


# skip over rtl and dev matches if topflavor is defined
# I'm not sure why this is here anymore :(.  I think it was supposed to 
# prevent mixed flavors from being included.

      if (defined $topflavor and $me->pkgtype() ne 'src') {
        if ($d->flavor() ne $topflavor and
            ($d->pkgtype() eq 'rtl' or
             $d->pkgtype() eq 'dev')) {
          $me->{'log'}->debug("Skipping because top flavor is $topflavor: ". $d->label()); 
          next;
        }
      }

      $me->match_dep(
                     deptype => $dt,
                     dep => $d,
                     table => $table,
                     missing => $missing,
                     topflavor => $topflavor
                    );

      # Heuristic for non static src builds
      if ($depenv !~ m!Static! and $dt =~ m!_link!) {

        next if defined $topflavor and $d->flavor() ne $topflavor;

        $me->{'log'}->debug("MATCH: Matching rtl's to Dep: " . $d->label())
        if defined $me->{'log'};
#       print "Scanning for rtl packages\n";

        $me->match_dep(
                       pkgtype => 'rtl',
                       deptype => $dt,
                       dep => $d,
                       table => $table,
                       missing => $missing,
                      );
      }
    }
  }
#  print "After ";
#  $me->printnode(full =>1);
}

sub match_dep {
  my ($me, %args) = @_;
  my ($pkgtype, 
      $deptype, 
      $dep, 
      $table, 
      $duplicates, 
      $missing,
      $topflavor) = (
                     $args{'pkgtype'}, 
                     $args{'deptype'}, 
                     $args{'dep'}, 
                     $args{'table'}, 
                     $args{'duplicates'},
                     $args{'missing'},
                     $args{'topflavor'},
                    );
  my $pkgs;
  my @matches;

  return if @{($me->get_dep_pkg(dep => $dep))} > 0 and ! defined $pkgtype;


  if ($me->match_me(%args)) {
    $me->{'log'}->inform("WARNING: PkgNode: Package " . $me->formnode() .
    "contains a dependency to itself");
    return;
  }

  # Check if src package is refering to itself
  return if $me->pkgtype() eq 'src' and $me->pkgname() eq $dep->pkgname();

# print "Matching Dep: ";
# $dep->printnode();

  my $flavor = $dep->flavor();
  $pkgtype = $dep->pkgtype() if ! defined $pkgtype;

  # Temporary Heuristic for flavors until the new DTD

  $flavor = ($pkgtype eq 'rtl' or $pkgtype eq 'dev') 
    ? $flavor : 'ANY';


  # Heuristic for noflavor here
  $flavor = 'ANY' if $flavor eq 'noflavor';

  # Heuristic if the source package has been specified with a flavor

  $flavor = $me->flavor() if $me->pkgtype eq 'src';


  my %queryargs = (pkgname => $dep->pkgname(), 
                   flavor => $flavor,
                   pkgtype => $pkgtype);





  #Heuristic for setup names
  if ($deptype eq 'Setup') {
    delete $queryargs{'pkgname'};
    $queryargs{'setupname'} = $dep->pkgname();
  }

  if (defined $me->{'log'}) {

    my $msg = "MATCH: Query with: ";

    for my $k (sort keys %queryargs) {
      $msg .= "/$k=$queryargs{$k}";
    }
    $msg .="\n";

    $me->{'log'}->debug($msg); 
  }

  $pkgs = $table->query(%queryargs);

  # Heuristic for pgm_static
  if ($dep->pkgtype() eq 'pgm') {
    $queryargs{'pkgtype'} = 'pgm_static';

  if (defined $me->{'log'}) {

    my $msg = "MATCH: Query with: ";

    for my $k (sort keys %queryargs) {
      $msg .= "/$k=$queryargs{$k}";
    }
    $msg .="\n";

    $me->{'log'}->debug($msg); 
  }
 
    my $staticpkgs = $table->query(%queryargs);
    push @$pkgs, @$staticpkgs;
  }


  # Heuristic for source packages
  $queryargs{'pkgtype'} ='src';

  if (defined $me->{'log'}) {

    my $msg = "MATCH: Query with: ";

    for my $k (sort keys %queryargs) {
      $msg .= "/$k=$queryargs{$k}";
    }
    $msg .="\n";

    $me->{'log'}->debug($msg); 
  }

  my $srcpkgs = $table->query(%queryargs);
  push @$pkgs, @$srcpkgs;



  if (defined $me->{'log'}) {

    my $msg = "MATCH: Query Results: \n";
    
    for my $p (@$pkgs) {
      $msg .= "\t" . $p->label() . "\n";
    }

    $me->{'log'}->debug($msg); 
  }


  @matches = grep {
    $dep->is_compatible($deptype eq 'Setup' ? 
                        $_->setupversion() : $_->version()
                       )} @$pkgs;


  if (@matches > 1) { 

    &$duplicates(pkg => $me, dep => $dep, dups => \@matches) if defined $duplicates;
  }

  if (! @matches) {
    &$missing(pkg => $me, missing => $dep, 
              flavor => $flavor, 
              pkgtype => $pkgtype,
              badversions => $pkgs,
             ) if defined $missing;
    return;
  }

  $me->{'log'}->debug("MATCH: Found Match: " . $matches[0]->label())
    if defined $me->{'log'};

  # Add links for dependency

# Select the best match
  my $mymatch = shift @matches;

  my @best = grep { $dep->flavor() eq $_->flavor() or 
                      $topflavor eq $_->flavor() or 
                        $me->flavor() eq $_->flavor() } @matches;

  $mymatch = shift @best if @best;

  $me->{'log'}->debug("MATCH: Found Best Match: " . $mymatch->label())
    if defined $me->{'log'};

  my $matchnode = new Grid::GPT::MatchNode(
                                           frompkg => $me,
                                           topkg => $mymatch,
                                           dep => $dep,
                                           flavor => $flavor,
                                           pkgtype => $pkgtype,
                                           dups => \@matches,
                                          );
  
  $mymatch->{'deptype'} = $dep->deptype();
  $me->{'pkgindexes'}->add_pkgnode(depnode => $matchnode,
                                   flavor => $matchnode->flavor(),
                                   pkgname => $matchnode->pkgname(),
                                   pkgtype => $matchnode->pkgtype(),
                               deptype => $dep->deptype());



  # Add provide links 
  $mymatch->{'provideindexes'}->
    add_pkgnode(depnode => $matchnode, 
                flavor => ($matchnode->frompkg())->flavor(),
                pkgname => ($matchnode->frompkg())->pkgname(),
                pkgtype => ($matchnode->frompkg())->pkgtype(),
                deptype => $dep->deptype());

}

sub add_filelist {
  my ($me, $obj) = @_;

  $me->{'filelist'} = $obj;
}

sub get_filelist {
  my ($me) = @_;

  return $me->{'filelist'};
}

sub setMasterFilelist
{
  my ($me, %args) = @_;

  $me->{'filelist'}->setMasterFilelist( mf => $args{'mf'} );
}

sub addToMasterFilelist
{
  my ($me) = @_;

  $me->{'filelist'}->addToMasterFilelist();
}

sub add_gptpkgfile {
  my ($me, $file) = @_;

  $me->{'gptpkgfile'} = $file;
}

sub gptpkgfile {
  my ($me, %args) = @_;

  return $me->{'gptpkgfile'} if defined $args{full};

  my ($basename) = $me->{'gptpkgfile'} =~ m!([^/]+)$!;

  return $basename;
}

sub set_format {
  my ($me, $format) = @_;
  $me->{'format'} = defined $format ? $format : 'gpt';
}



sub get_dep_pkg {
  my ($me, %args) = @_;

  my $matches = $me->{'pkgindexes'}->query(
                                           flavor => $args{'flavor'},
                                           pkgtype => $args{'pkgtype'},
                                           nodesub => sub {
                                             return $args{'dep'}->is_same($_->dep());
                                           });

  return match2pkglist(matches => $matches);
}

sub match_me {
  my ($me, %args) = @_;
  my ($deptype, $dep) = (
               defined $args{'deptype'} ? $args{'deptype'} : "N/A", 
               $args{'dep'}, 
               );


  return 0 if defined $me->setupname()  && 
    $me->setupname() ne $dep->pkgname() && 
      $deptype eq 'Setup';
  return 0 if $me->pkgname() ne $dep->pkgname() && $deptype ne 'Setup';
  return 0 if defined $dep->flavor() && $me->flavor() ne $dep->flavor();
  return 0 if $me->pkgtype() ne $dep->pkgtype();
  return 1;

}


sub query_dep_matches {
  my ($me, %args) = @_;
    return $me->{'pkgindexes'}->query(%args);
}

sub query_dep_pkgs {
  my ($me, %args) = @_;

  my $matches = $me->query_dep_matches(%args);

  return match2pkglist(matches => $matches, 
                       flavor =>$args{'preferred_flavor'});

}
sub query_provide_pkgs {
  my ($me, %args) = @_;

  my $matches = $me->query_provide_matches(%args);

  return match2pkglist(matches => $matches,  from =>1 );

}

sub query_deps {
  my ($me, %args) = @_;
    return $me->{'depindexes'}->query(%args);
}


sub query_provide_matches {
  my ($me, %args) = @_;
    return $me->{'provideindexes'}->query(%args);
}

sub match2pkglist {
  my (%args) = @_;
  my ($matches, $from, $flavor) = ($args{'matches'}, 
                                   $args{'from'},
                                   $args{'flavor'},
                                  );

  my @rawpkgs;
  if (defined $from) {
    @rawpkgs = map {$_->frompkg() } @$matches;
  } else {
    for my $m (@$matches) {
      my @candidates =  ($m->topkg());
      push @candidates, @{ $m->{'dups'} };
      if (defined $flavor) {
        my @preferred = grep { $_->flavor eq $flavor } @candidates;
        if (@preferred) {
          push @rawpkgs, @preferred;
          next;
        }
      }
      push @rawpkgs, @candidates;
    }
  }
  my @pkgs;
  for my $p(@rawpkgs) {
    push @pkgs, $p if ! grep {$p->is_same($_)} @pkgs;
  }
  return \@pkgs;
}

sub init_matches {
  my ($me) = @_;

  my $matches = $me->{'pkgindexes'}->query();
  # exclude src self deps from count.
  $me->{'matches'} = 
    [ grep { ! ($_->frompkg())->is_same($_->topkg()) } @$matches ];
  
}


sub label {
  my($me, %args) = @_;

  if (defined $args{'href'}) {
    my $href = $me->pkgname() . $me->flavor() . $me->pkgtype();
    return  "<a href=./deptable.html#$href>" . $me->Grid::GPT::BaseNode::label() . "</a>";
  }
  my $result = $me->Grid::GPT::BaseNode::label();
  return $result if ! defined $args{'full'};
  $result .= " " . $me->{'depnode'}->version_label();
  return $result;

}


sub count_matched_pkgs {
  my ($me) = @_;

  my @matches;
  for my $m (@{$me->{'matches'}}) {
    # The same package name and type with different flavors count as one package
    push @matches, $m 
      if ! grep { ($_->topkg())->pkgname() eq ($m->topkg())->pkgname() and 
		    ($_->topkg())->pkgtype() eq ($m->topkg())->pkgtype()} 
	@matches;
  }

  return scalar(@matches);
}


sub printmatches {
  my ($me, %args) = @_;

  print "Matches for ", $me->label(), ":\n";
  for my $m(@{$me->{'matches'}}) {
    $m->printnode(%args);
  }
}

sub formmatches {
  my ($me, %args) = @_;

  my $msg = "Matches for " . $me->label() . ":\n";
  for my $m(@{$me->{'matches'}}) {
    $msg .= "\t" . $m->formnode(%args) . "\n";
  }
  return $msg;
}

sub remove_matches {
  my ($me, $pkg) = @_;

  my @matches = grep { ! $pkg->is_same($_->topkg()) } @{$me->{'matches'}};

  $me->{'matches'} = \@matches;

}

sub matchcount {
  my ($me) = @_;

  return scalar(@{$me->{'matches'}});

}


sub version_label {
  my ($me) = @_;

  return $me->{'version'}->label();
}

sub check4src_selfdeps {
  my ($me) = @_;
  return 0 if $me->pkgtype() ne 'src';
  
  return 0 if ! defined $me->{'depindexes'};

  my $deps = $me->{'depindexes'}->query(pkgname => $me->pkgname());

  return 0 if ! defined $deps;

  return scalar(@$deps);
}

sub get_buildenv {
  my ($me) = @_;
  return {ext_libs => $me->{'depnode'}->external_libs(),
         pkg_libs => $me->{'depnode'}->pkg_libs(),
         includes => $me->{'depnode'}->external_includes(),
         cflags => $me->{'depnode'}->cflags(),
         };

}

sub printnode {
  my($me, %args) = @_;

  return $me->printnodehtml(href => 1) if defined $args{'href'};
#  print "/deptype=$me->{'deptype'}:" 
#    if defined $me->{'deptype'};
  
#  print "/providetype=$me->{'providetype'}:" 
#    if defined $me->{'providetype'};
  
  print "/setupname=$me->{'setupname'}:" if defined $me->{'setupname'};

  $me->Grid::GPT::BaseNode::printnode();
  return if ! defined $args{'full'} and ! defined $args{'pretty'};
  print "Dependencies:\n";
  print "----------\n";
  $me->{'pkgindexes'}->printtable(to => $args{'pretty'});
  print "----------\n";
  print "Provides:\n";
  print "----------\n";
  $me->{'provideindexes'}->printtable(from => $args{'pretty'});
  print "----------\n";
  return;
}

sub formnode {
  my($me, %args) = @_;
  my $msg;
  $msg .= "/setupname=$me->{'setupname'}:" if defined $me->{'setupname'};

  $msg .= $me->Grid::GPT::BaseNode::label() . "\n";
  return $msg if ! defined $args{'full'} and ! defined $args{'pretty'};

  if (@{$me->{'pkgindexes'}->{'deps'}}) {
    $msg .= "Dependencies:\n";
    $msg .=  "----------\n";
    $msg .=  $me->{'pkgindexes'}->formtable(to => $args{'pretty'});
    $msg .=  "----------\n";
  } else {
    $msg .= "Dependencies: None\n";
  }

  if (@{$me->{'provideindexes'}->{'deps'}}) {
    $msg .=  "Provides:\n";
    $msg .=  "----------\n";
    $msg .=  $me->{'provideindexes'}->formtable(from => $args{'pretty'});
    $msg .=  "--------------------------------------------------------------\n";
  } else {
    $msg .=  "Provides: None\n";    
  }
  return $msg;
}

sub printnodehtml {
  my($me, %args) = @_;
  my $href = $me->pkgname() . $me->flavor() . $me->pkgtype();

  if (defined $args{'href'}) {
    print "<a href=./deptable.html#$href>", $me->label(), "</a>\n";
    next;
  }

  print "<h2><a name=$href></a>";
  $me->printnode();
  print "</h2>\n";

  print "<h3>Version:</h3>",$me->{'depnode'}->version_label(), "\n";
  print "<h3>Dependencies:</h3>\n";
  print "<hr>\n";
  $me->{'depindexes'}->printtable(versions =>1);
  print "<hr>\n";
  print "<h3>Dependencies:</h3>\n";
  $me->{'pkgindexes'}->printtable(to => 1, html => 1);
  print "<hr>\n";
  print "<h3>Provides:</h3>\n";
  $me->{'provideindexes'}->printtable(from => 1, html => 1);
  print "<hr><br><br>\n";


}

sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an obj";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in obj of class $type";
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

Grid::GPT::DepNode - Perl extension for managing the dependencies in binary packages

=head1 SYNOPSIS

  use Grid::GPT::DepNode;
  my $dep = new Grid::GPT::DepNode(versions => \@versions, 
						       name => $name,
						       type => $type,
						       pkg_type => $pkg_type,
						       my_pkg_type => $my_pkg_type);
  my $result = $dep->fulfills_dependency($name, $version, $pkg_type);

=head1 DESCRIPTION

I<Grid::GPT::DepNode> is used to encapsulate a dependency
that one binary package has to another dependency.  These dependencies
are seperated into the following types:

=over 4

=item Compile

Dependency occurs when the package is used for compiling.  Usually
caused by header files including headers from other packages.

=item Build_Link

Dependency occurs when the package is linked to other applications.
This commonly known as dependent libraries.  

=item Regeneration

Dependency occurs when a statically built package needs to be rebuilt
because of updates to dependent packages.  This results in a new
binary package even though nothing inside the package has changed and
the version number has not been updated.

=item Runtime_Link

Dependency occurs when a package needs to load another package's binary at run-time.

=item Runtime

Dependency occurs when a package needs to read a file or execute a
program from another package.

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::DepNode> obj.  The function has the following named objs:

=over 4

=item versions

Reference to an array of L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> objs.

=item name

Name of the dependent package.

=item type

The type of dependency.

=item pkg_type

The binary package type of the dependent package.

=item my_pkg_type

The binary package type of the package owning this dependency.

=back

=item fulfills_dependency(name, version, pkg_type)

Returns a 1 if the arguments met the requirements of the
dependency. Returns a 0 if not.  Note that package types pgm and
pgm_static are considered equivalent.

=item write_tag(xml_obj)

Adds dependency contents into an L<Grid::GPT::XML|Grid::GPT::XML> obj. 


=item convert_dependency_hash2xml(dependency_hash_reference, xml_obj)

Class function which adds the contents of all dependency objs in a
hash reference to an L<Grid::GPT::XML|Grid::GPT::XML> obj.

=item create_dependency_hash(xml_obj, package_type_of_dependency_owner)

This is a class function which creates a hash of
I<Grid::GPT::DepNode> objs out of an
L<Grid::GPT::XML|Grid::GPT::XML> obj.  The key to each hash entry
is of the form <name>_<pkg_type>.

=back

=head1 ToDo

=over 4

=item The internal validate function has not been tested. 

=back

=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::XML(1) Grid::GPT::V1::Version(1).

=cut
