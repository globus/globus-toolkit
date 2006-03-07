package Grid::GPT::PkgMngmt::Inform;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Data::Dumper;
use Cwd;
use Carp qw(cluck);

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
$VERSION = '0.01';

# Preloaded methods go here.
sub new {
  my ($class, %args) = @_;
  my $me = {
	    verbose => $args{'verbose'},
	    debug => $args{'debug'},
	    log => $args{'log'},
            name => $args{'name'},
            suppress_clean_errors => 1,
	   };

  

  if (! defined $me->{'verbose'}) {
    $me->{'verbose'} = defined $me->{'debug'} ? $me->{'debug'} : 0;
  }

  $|++;
  bless $me, $class;

  if (defined $me->{'log'}) {

    # build_gpt and friends do not use FilelistFunctions
    if ( defined eval "require Grid::GPT::FilelistFunctions" ) {

      require  Grid::GPT::FilelistFunctions;

      $me->{'log'} = Grid::GPT::FilelistFunctions::abspath($me->{'log'});
    }
    my $result = `rm -f $me->{'log'} if -f $me->{'log'}`;
    $me->{'starttime'} = time;
    my @date = split /\s+/, localtime;
    $me->announce("$me->{'name'}: started $date[1].$date[2].$date[4]  $date[3]");
  }
  return $me;
}

sub inform {
  my ($me, $content, $override, $fh) = @_;
  $override = 0 if ! defined $override;

  cluck "content is undefined\n" if ! defined $content;

  if (defined $me->{'log'}) {
    open (LOG, ">>$me->{'log'}") || die "ERROR: Could not open $me->{'log'}\n";
    print LOG "$content\n";
    close LOG;
  } else {
    print "$content\n" if $me->{'verbose'} or $override;
    print $fh "$content\n" if defined $fh and 
      ($me->{'verbose'} or $override);
  }
}
# Hack because sometimes I don't want a carriage return printed.

sub inform_piece {
  my ($me, $content, $override, $fh) = @_;
  $override = 0 if ! defined $override;

  if (defined $me->{'log'}) {
    open (LOG, ">>$me->{'log'}") || die "ERROR: Could not open $me->{'log'}\n";
    print LOG "$content\n";
    close LOG;
  } else {
    print "$content" if $me->{'verbose'} or $override;
    print $fh "$content\n" if defined $fh and 
      ($me->{'verbose'} or $override);
  }
}

sub debug {
  my ($me, $content, $fh) = @_;

  return if ! defined $me->{'debug'};

  if (defined $me->{'log'}) {
    open (LOG, ">>$me->{'log'}") || die "ERROR: Could not open $me->{'log'}\n";
    print LOG "$content\n";
    close LOG;
  } else {
    print "$content\n";
    print $fh "$content\n" if defined $fh;
  }
}

sub error {
  my ($me, $content, $fh) = @_;

  if (defined $me->{'log'}) {
    open (LOG, ">>$me->{'log'}") || die "ERROR: Could not open $me->{'log'}\n";
    print LOG "$content\n";
    close LOG;
  }

    print STDERR "$content\n";
    print $fh "$content\n" if defined $fh;
}

sub announce {
    my ($me, $content) = @_;
    $me->inform("");
    $me->inform("$me->{'name'} ====> ". $content, 1); 
}

sub action {
  my ($me, $command, $suppress_error) = @_;

  # Log the step
  $me->inform($command);
  
  my $result;
  # Perform the step
  if (defined $me->{'log'}) {
    # Save original STDERR as KCYHL_ERR.  'KCYHL' is just an unusual
     # prefix that is unlikely to clash with any other filehandle.
     open KCYHL_ERR, ">&STDERR";
     open (STDERR, ">gpt_errorlog") or die "Couldn't open gpt_errorlog:$!";
     my $output = `$command`;
     $result = $?;
     # Restore original STDERR
     open STDERR, ">&KCYHL_ERR";

     open (ERRLOG, "gpt_errorlog");

    for my $l (<ERRLOG>) {
      $output .= $l;
    }
    close ERRLOG;
    $me->inform($output);
  } else {
    if ($me->{'verbose'}) {
      system($command);
    } else {
      my $output = `$command 2>&1`;

      # if $? = -1, then $command failed to run, and would have produced
      # no output (which causes inform() to chirp).  Print out $! instead
      if ( $? eq -1 ) {
         $output = $!;
      }

      $me->inform($output);
      if ($? and ! $me->{'verbose'} and ! defined $suppress_error and
         ! ($command =~ m!make.+clean! and $me->{'suppress_clean_errors'})) {
        $me->inform($command,1);
        $me->inform($output, 1);
      }
    }
    $result = $?;
  }
  return 0 if ($command =~ m!make.+clean! 
               and $me->{'suppress_clean_errors'});
  return $result;

}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::PkgMngmt:Inform - Perl extension for informing globus binaries.

=head1 SYNOPSIS

  use Inform;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Inform was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
