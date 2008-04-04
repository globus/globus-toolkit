package Grid::GPT::FilelistSort;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

#
# NOTE: Filelist.pm will be altered in a future release to include a completely
# different set of functions related directly to the Filelist functionality.
#
# This means that this file will be deprecated!  Please use FilelistSort.pm
# in place of Filelist.pm!
#
# NOTE 2: Please make any changes to FilelistSort.pm that you make to Filelist.pm
# (and vice versa) until Filelist.pm this change occurs.
#

require Exporter;
require AutoLoader;
require Grid::GPT::PkgMngmt::Inform;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';


# Preloaded methods go here.
sub new {
  my ($class, %arg) = @_;
  my $log = $arg{'log'};
  $log = new Grid::GPT::PkgMngmt::Inform() if ! defined $log;
  my $me = {
	    fulllist => [],
	    flavor => $arg{'flavor'},
	    log => $log,
            rootfile_supression => $arg{'rootfile_supression'},
	   };
  bless $me, $class;

  for (@{$arg{'list'}}) {
    next if ! m!\w!;
    my $entry = {};
    m!(.*)/([^/]+)$!;
    $entry->{'name'} = $2;
    $entry->{'dir'} = $1;
    chomp($entry->{'name'});
    push @{$me->{'fulllist'}}, $entry;
  }

  $me->reset();
  return $me;
}

sub reset {
  my $self = shift;
  $self->{'list'} = [];
##  @{$self->{'list'}} = grep { $_->{'dir'} !~ m!etc/globus_packages/! }
  @{$self->{'list'}} = grep { $_->{'dir'} !~ m!etc/gpt/packages/! }
    grep { $_->{'dir'} !~ m!etc/globus_packages/! }
      @{$self->{'fulllist'}};

# need to leave this because of bug that leaves noinst files in the root dir.
  @{$self->{'list'}} = grep { $_->{'dir'} =~ m!\w+!  
                                or $_->{'name'} =~ m!\.xml!
                                  or $_->{'name'} =~ m!\.wsdd!
                                    or $_->{'name'} =~ m!setenv!
                                      or $_->{'name'} =~ m!\.properties! } 
    @{$self->{'list'}};

}

sub flavored_files {
  my $self = shift;
  my $f = $self->{'flavor'};
  my $list = $self->{'list'};
  my @newlist;
  
  for (@{$list}) {
    if ($_->{'name'} =~ /[_-]$f/ and $_->{'name'} !~ /\.h$/) {
      push @newlist, $_;
      next;
    }
    if ($_->{'dir'} =~ /[_-]$f/ and $_->{'name'} =~ /\.h$/) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub noflavor_files {
  my $self = shift;
  my $f = $self->{'flavor'};
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} !~ /[_-]$f/ and $_->{'name'} !~ /\.h$/) {
      push @newlist, $_;
      next;
    }
    if ($_->{'dir'} !~ /[_-]$f/ and $_->{'name'} =~ /\.h$/) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub flavored_headers {
  my $self = shift;
  my $f = $self->{'flavor'};
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} =~ /\.h$/ and $_->{'dir'} =~ m!include/$f!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}
sub noflavor_headers {
  my $self = shift;
  my $f = $self->{'flavor'};
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} =~ /\.h$/ and $_->{'dir'} !~ m!include/$f!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_programs {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'dir'} =~ m!(?:/|^)(?:s?bin|libexec|test)(?:/|$)!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_setup_files {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'dir'} =~ m!^/setup/!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_static_libs {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} =~ /\.a$/ and $_->{'dir'} =~ m!lib/!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_dynamic_libs {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ( ( $_->{'name'} =~ m!\.so! 
           or $_->{'name'} =~ m!\.sl! 
           or $_->{'name'} =~ m!\.dylib! ) 
         and $_->{'name'} =~ m!^lib!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_perl_modules {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} =~ m!\.pm! and $_->{'dir'} =~ m!lib!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_libtool_libs {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'name'} =~ /\.la$/ and $_->{'name'} =~ m!^lib!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_docs {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
    if ($_->{'dir'} =~ m!(?:/|^)(?:share/doc|man)(?:/|$)!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub extract_data {
  my $self = shift;
  my $list = $self->{'list'};
  my @newlist;
  for (@{$list}) {
##    if ($_->{'dir'} !~ m!(?:/|^)(?:share/doc|man|s?bin|libexec|include|lib|setup|etc/globus_packages)(?:/|$)!) {
    if ($_->{'dir'} !~ m!(?:/|^)(?:share/doc|man|s?bin|libexec|include|lib|setup|etc/gpt/packages)(?:/|$)!) {
      push @newlist, $_;
    }
  }
  $self->{'list'} = \@newlist;
}

sub add_package_metadata_files {
  my ($self, $type, $flavor) = @_;
  $flavor = $self->{'flavor'} if !defined($flavor);

  for my $f (@{$self->{'fulllist'}}) {
    if ($f->{'name'} eq "$ {flavor}_$type.filelist" or 
	$f->{'name'} eq "pkg_data_$ {flavor}_$type.gpt") {
      push @{$self->{'list'}}, $f;
    }
  }
}

sub get_list {
  my $self = shift;
  my @list;
  for my $f (@{$self->{'list'}}) {
    my $line = $f->{'dir'} . "/" . $f->{'name'};

    if (grep { $line eq $_ } @list) {
      next if ! defined $self->{'log'};
      $self->{'log'}->inform("WARNING: $line is a duplicate file entry\n",1);
      next;
    }

    push @list, $line;
  }
  return \@list;
}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Filelist - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Filelist;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Filelist was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
