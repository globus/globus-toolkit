#
# Globus::GRAM::JobManager
#
# CVS Information:
#     $Source$
#     $Date$
#     $Revision$
#     $Author$
#
use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobSignal;
use Globus::Core::Paths;

use IO::File;
use File::Path;

=head1 NAME

Globus::GRAM::JobManager - Base class for all Job Manager scripts

=head1 SYNOPSIS

$manager = new Globus::GRAM::JobManager($job_description);

$manager->log("Starting new operation");
$manager->submit();

=head1 DESCRIPTION

The Globus::GRAM::JobManager module implements the default behavior
for a Job Manager scheduler interface.

=cut

package Globus::GRAM::JobManager;

=head2 $manager = new Globus::GRAM::JobManager(I<$JobDescription>)

Constructor for the Globus::GRAM::JobManager. This constructor expects
to be passed a parameter consisting of a reference to a
Globus::GRAM::JobDescription.

=cut
sub new
{
    my $class = shift;
    my $self = {};
    my $description = shift;

    $self->{JobDescription} = $description;

    if(defined($description->logfile()))
    {
	$self->{log} = new IO::File($description->logfile(), '>>');
	$self->{log}->autoflush();
    }

    bless $self, $class;
}

=head2 $manager->log(I<$string>)

Log a message to the job manager log file. This is intended for use by
subclasses of the JobManager class. A newline will be appended to the
log message.

=cut

sub log
{
    my $self = shift;

    if(exists($self->{log}))
    {
	$self->{log}->print(scalar(localtime(time)), " JM_SCRIPT: ", @_, "\n");
    }

    return;
}

sub respond
{
    my $self = shift;
    my $result = shift;
    my $var;

    foreach (keys %{$result})
    {
	$var = uc($_);
	print "GRAM_SCRIPT_$var:" . $result->{$_} . "\n";
    }
}

=head2 $manager->submit()

Submit a job request to the scheduler. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to submit the job to the
scheduler.

A scheduler which implements this method should return a hash reference
containing the values JOB_STATE and JOB_ID if the job request is
successful; otherwise a Globus::GRAM::Error value should be returned.
For example:

    return {JOB_STATE => Globus::GRAM::JobState::PENDING,
            JOB_ID => $job_id};

=cut

sub submit
{
    my $self = shift;

    $self->log("Job Manager module does not implement 'submit'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=head2 $manager->poll()

Poll a job's status. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to poll the
scheduler.

A scheduler which implements this method should return a hash reference
containing job_state.

=cut

sub poll
{
    my $self = shift;

    $self->log("Job Manager module Script does not implement 'poll'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=head2 cancel

Remove a job. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to remove the job
from the scheduler.

=cut

sub cancel
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'cancel'\n");
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
    my $scratch_prefix;
    my $scratch_suffix;
    my @acceptable=split(//, "abcdefghijklmnopqrstuvwxyz".
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
			     "0123456789");
    
    srand();

    $self->log(
        "Entering Job Manager default implementation of make_scratchdir");

    $scratch_prefix = $description->scratch_dir_base();
    $scratch_suffix = $description->scratch_dir();

    if($scratch_suffix =~ m,^/,,)
    {
	$scratch_prefix = $scratch_suffix;
    }
    elsif ($scratch_suffix !~ m,/$,,)
    {
	$scratch_prefix .= "/$scratch_suffix";
    }
    else
    {
	$scratch_prefix .= $scratch_suffix;
    }

    if(! -w $scratch_prefix)
    {
	return Globus::GRAM::Error::BAD_DIRECTORY;
    }

    while(!$created)
    {
        # Files with names comprised of Ascii values 48-122 should be
	# relatively easy to remove from the shell if things go bad.
	$tmpname = 'gram_scratch_' .
	           $acceptable[rand() * $#acceptable] .
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

sub file_cleanup
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $scratch_directory;
    my $count;

    $self->log(
        "Entering Job Manager default implementation of file_cleanup");
    foreach ($description->file_cleanup())
    {
	if(!defined($_))
	{
	    next;
	}
	$self->log("Removing $_");

        if(-d $_)
	{
	    $count = File::Path::rmtree($scratch_directory);
	}
	else
	{
	    unlink($_);
	}
    }

    return {};
}

sub rewrite_urls
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $url;
    my $filename;

    foreach ('stdin', 'executable')
    {
	chomp($url = $description->$_());
	if($url =~ m|^[a-zA-Z]+://|)
	{
	    chomp($filename = `$cache_pgm -query $url`);
	    if($filename ne '')
	    {
		$description->add($_, $filename);
	    }
	}
    }
    return 0;
}

sub stage_in
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $url_copy = "$Globus::Core::Paths::bindir/globus-url-copy";
    my $tag = $ENV{GLOBUS_GRAM_JOB_CONTACT};
    my ($remote, $local, $cached);

    if($description->executable() =~ m|^[a-zA-Z]+://|)
    {
	$remote = $description->executable();
	if(system("$cache_pgm -add -t $tag $remote >/dev/null 2>&1") != 0)
	{
	    return Globus::GRAM::Error::STAGING_EXECUTABLE;
	}
    }
    if($description->stdin() =~ m|^[a-zA-Z]+://|)
    {
	$remote = $description->stdin();
	if(system("$cache_pgm -add -t $tag $remote >/dev/null 2>&1") != 0)
	{
	    return Globus::GRAM::Error::STAGING_STDIN;
	}
    }
    foreach ($description->file_stage_in())
    {
	if(!defined($_))
	{
	    next;
	}
	($remote, $local) = ($_->[0], $_->[1]);

	if($local !~ m|^/|)
	{
	    $local = $description->directory() . '/' . $local;
	}

	if(system("$url_copy $remote file://$local >/dev/null 2>&1") != 0)
	{
	    return Globus::GRAM::Error::STAGE_IN_FAILED;
	}
	$self->respond({'STAGED_IN' => "$remote $local"});
    }
    foreach($description->file_stage_in_shared())
    {
	if(!defined($_))
	{
	    next;
	}
	($remote, $local) = ($_->[0], $_->[1]);

	if($local !~ m|^/|)
	{
	    $local = $description->directory() . '/' . $local;
	}

	if(system("$cache_pgm -add -t $tag $remote >/dev/null 2>&1") == 0)
	{
	    chomp($cached = `$cache_pgm -query $remote`);
	    symlink($cached, $local);
	}
	else
	{
	    return Globus::GRAM::Error::STAGE_IN_FAILED;
	}
	$self->respond({'STAGED_IN_SHARED' => "$remote $local"});
    }
    return {};
}

sub stage_out
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $url_copy = "$Globus::Core::Paths::bindir/globus-url-copy";
    my $tag = $ENV{GLOBUS_GRAM_JOB_CONTACT};
    my ($remote, $local, $cached);

    foreach ($description->file_stage_out())
    {
	if(!defined($_))
	{
	    next;
	}
	($local, $remote) = ($_->[0], $_->[1]);

	if($local !~ m|^/|)
	{
	    $local = $description->directory() . '/' . $local;
	}

	if(system("$url_copy file://$local $remote >/dev/null 2>&1") != 0)
	{
	    return Globus::GRAM::Error::STAGE_IN_FAILED;
	}
	$self->respond({'STAGED_OUT' => "$local $remote"});
    }
    return {};
}
1;
