=head1 NAME

JobManager - Base class for all Job Manager scripts

=head1 SYNOPSIS

$manager = new Globus::GRAM::JobManager($job_description);

$manager->log("Starting new operation");

=head1 DESCRIPTION

The Globus::GRAM::JobManager module implements the default behavior
for a job manager scheduler interface, and provides a parser for the

=cut

use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobSignal;
use IO::File;
use File::Path;

package Globus::GRAM::JobManager;

=head2 new

Constructor for the Globus::GRAM::JobManager. This constructor expects
to be passed a parameter consisting of a reference to a
Globus::GRAM::JobDescription.

=cut
sub new($$)
{
    my $class = shift;
    my $self = {};
    my $description = shift;

    $self->{JobDescription} = $description;

    if(exists($description->{logfile}))
    {
	$self->{log} = new IO::File($description->{logfile}, '>>');
    }

    bless $self, $class;
}

=head2 log

Log a message to the job manager log file. This is intended for use by
subclasses of the JobManager class. A newline will be appended to the
log message.

=cut
sub log($@)
{
    my $self = shift;

    if(exists($self->{log}))
    {
	$self->{log}->print(@_, "\n");
    }

    return;
}

=head2 submit

Submit a job request to the scheduler. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to submit the job to the
scheduler.

=cut
sub submit($)
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'submit'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=head2 poll

Poll a job's status. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to poll the
scheduler.

=cut
sub poll
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'poll'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=head2 rm

Remove a job. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to remove the job
from the scheduler.

=cut
sub rm
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'rm'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=head2 signal

Signal a job. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to remove the job
from the scheduler. This method is passed a parameter containin the
signal number, as well as the signal-specific parameters.

=cut
sub signal
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'signal'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

sub make_scratchdir
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $created = 0;
    my $tmpnam;
    my $dirname;
    my @acceptable=split(//, "abcdefghijklmnopqrstuvwxyz".
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
			     "0123456789");
    
    srand();

    $self->log(
        "Entering Job Manager default implementation of make_scratchdir");

    $scratch_prefix = $description->scratch_dir_base();

    if(! -w $scratch_prefix)
    {
	return Globus::GRAM::Error::BAD_DIRECTORY;
    }

    while(!$created)
    {
        # Files with names comprised of Ascii values 48-122 should be
	# relatively easy to remove from the shell if things go bad.
	$tmpname = "gram" . $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable];
	$dirname = "$scratch_prefix/$tmpname";
	$self->log(
	    "Trying to create directory named $dirname");
	$created = mkdir($dirname, 0700);
	if($created)
	{
	    $self->log("I think it was made.... verifying");
	    if (-l $dirname || ! -d $dirname || ! -o $dirname)
	    {
		$self->log("nope, somebody's messing with us.");
		$created = 0;
	    }
	}
    }
    $self->log("Using $dirname as the scratch directory for this job.");

    return {SCRATCH_DIR => $dirname};
}

sub remove_scratchdir
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $scratch_directory;
    my $count;


    $scratch_directory = $description->scratch_directory();
    $self->log(
        "Entering Job Manager default implementation of remove_scratchdir");
    $self->log("Removing $scratch_directory");
    $count = File::Path::rmtree($scratch_directory);
    $self->log("Removed $count files");

    return {};
}

1;
