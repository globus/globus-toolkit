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

use POSIX;
use IO::File;
use File::Path;
use File::Copy;

package Globus::GRAM::JobManager;

=head1 NAME

Globus::GRAM::JobManager - Base class for all Job Manager scripts

=head1 SYNOPSIS

 $manager = new Globus::GRAM::JobManager($job_description);

 $manager->log("Starting new operation");
 $manager->respond($hashref);
 $hashref = $manager->submit();
 $hashref = $manager->poll();
 $hashref = $manager->cancel();
 $hashref = $manager->signal();
 $hashref = $manager->make_scratchdir();
 $hashref = $manager->remove_scratchdir();
 $hashref = $manager->rewrite_urls();
 $hashref = $manager->stage_in();
 $hashref = $manager->stage_out();
 $hashref = $manager->cache_cleanup();
 $hashref = $manager->remote_io_file_create();
 $hashref = $manager->proxy_relocate();
 $hashref = $manager->proxy_update();
 $manager->append_path($hash, $variable, $path);

=head1 DESCRIPTION

The Globus::GRAM::JobManager module implements the base behavior
for a Job Manager script interface. Scheduler-specific job manager
scripts must inherit from this module in order to be used by the job
manager.

=head2 Methods

=over 4

=item $manager = Globus::GRAM::JobManager->new($JobDescription)

Each Globus::GRAM::JobManager object is created by calling the constructor
with a single argument, a Globus::GRAM::JobDescription object containing
the information about the job request which the script will be modifying.
Modules which subclass Globus::GRAM::JobManager MUST call the super-class's
constructor, as in this code fragment:

     my $proto = shift;
     my $class = ref($proto) || $proto;
     my $self = $class->SUPER::new(@_);

     bless $self, $class;

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

    $self->log("New JobManager created.");

    return $self;
}

=item $manager->log($string)

Log a message to the job manager log file. The message is preceded by
a timestamp.

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

=item $manager->respond($message)

Send a response to the job manager program. The response may either be
a hash reference consisting of a hash of (variable, value) pairs, which will
be returned to the job manager, or an already formatted string.
This only needs to be directly called by a job manager implementation
when the script wants to send a partial response while processing one of
the scheduler interface methods (for example,
to indicate that a file has been staged). 

The valid keys for a response are defined in the RESPONSES section.

=cut

sub respond
{
    my $self = shift;
    my $result = shift;
    my $var;

    if(!ref($result))
    {
	print $result;
    }
    else
    {
	foreach (keys %{$result})
	{
	    $var = uc($_);
	    print "GRAM_SCRIPT_$var:" . $result->{$_} . "\n";
	}
    }
}

=item $manager->submit()

Submit a job request to the scheduler. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to submit the job to the
scheduler.

A scheduler which implements this method should return a hash reference
containing the values JOB_STATE and JOB_ID if the job request is
successful; otherwise a Globus::GRAM::Error value should be returned.
The job state values are defined in the Globus::GRAM::JobState module. The
job parameters are defined in $self->{JobDescription}.

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

=item $manager->poll()

Poll a job's status. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to poll the
scheduler.

A scheduler which implements this method should return a hash reference
containing the JOB_STATE value. The job's ID can be accessed by calling the
$self->{JobDescription}->jobid() method.

=cut

sub poll
{
    my $self = shift;

    $self->log("Job Manager module Script does not implement 'poll'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=item $manager->cancel()

Cancel a job. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to remove the job
from the scheduler.

A scheduler which implements this method should return a hash reference
containing the JOB_STATE value. The job's ID can be accessed by calling the
$self->{JobDescription}->jobid() method.

=cut

sub cancel
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'cancel'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=item $manager->signal()

Signal a job. The default implementation returns
with the Globus::GRAM::Error::UNIMPLEMENTED error. Scheduler specific
subclasses should reimplement this method to remove the job
from the scheduler. The JobManager module can determine the job's ID,
the signal number, and the (optional) signal arguments from the
Job Description by calling it's job_id(), signal(), and and signal_arg()
methods, respectively.

Depending on the signal, it may be appropriate for the JobManager object
to return a hash reference containing a JOB_STATE update.

=cut

sub signal
{
    my $self = shift;

    $self->log("Job Manager Script does not implement 'signal'\n");
    return Globus::GRAM::Error::UNIMPLEMENTED;
}

=item $manager->make_scratchdir()

Create a scratch directory for a job. The scratch directory location
is based on the JobDescription's scratch_dir_base() and scratch_dir() methods.

If the scratch_dir() value is a relative path, then a directory will be
created as a subdirectory of scratch_dir_base()/scratch_dir(), otherwise,
it will be created as a subdirectory of scratch_dir().  This method will
return a hash reference containing mapping SCRATCH_DIR to the absolute
path of newly created scratch directory if successful. 

=cut

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
	return Globus::GRAM::Error::INVALID_SCRATCH;
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

=item $manager->make_scratchdir()

Delete a job's scratch directory. All files and subdirectories of the
JobDescription's scratch_directory() will be deleted.

=cut

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

=item $manager->make_scratchdir()

Delete some job-related files. All files listed in the JobDescription's
file_cleanup() array will be deleted.

=cut

sub file_cleanup
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $count;

    $self->log(
        "Entering Job Manager default implementation of file_cleanup");
    foreach ($description->file_cleanup())
    {
	if(!defined($_))
	{
	    next;
	}
	if(ref($_))
	{
	    return Globus::GRAM::Error::RSL_FILE_CLEANUP();
	}
	$self->log("Removing $_");

	unlink($_);
    }

    return {};
}

=item $manager->rewrite_urls()

Looks up URLs listed in the JobDescription's stdin() and executable(), and
replaces them with paths to locally cached copies.

=cut

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
    return {};
}


=item $manager->stage_in()

Stage input files need for the job from remote storage. The files to
be staged are defined by the array of [URL, path] pairs in
the job description's file_stage_in() and file_stage_in_shared() methods.
The Globus::GRAM::JobManager module provides an implementation of this
functionality using the globus-url-copy and globus-gass-cache programs.
Files which are staged in are not automatically removed when the job
terminates.

This function returns intermediate responses using the
Globus::GRAM::JobManager::response() method to let the job manager know when
each individual file has been staged.

=cut

sub stage_in
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $url_copy = "$Globus::Core::Paths::bindir/globus-url-copy";
    my $tag = $description->cache_tag() or $ENV{GLOBUS_GRAM_JOB_CONTACT};
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

=item $manager->stage_out()

Stage output files generated by this job to remote storage. The files to
be staged are defined by the array of [URL, destination] pairs in
the job description's file_stage_out() method. The Globus::GRAM::JobManager
module provides an implementation of this functionality using the
globus-url-copy program.  Files which are staged out are not removed by this
method.

=cut

sub stage_out
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $url_copy = "$Globus::Core::Paths::bindir/globus-url-copy";
    my $tag = $description->cache_tag() or $ENV{GLOBUS_GRAM_JOB_CONTACT};
    my $local_path;

    foreach ($description->file_stage_out())
    {
	if(!defined($_))
	{
	    next;
	}
	($local, $remote) = ($_->[0], $_->[1]);

	# handle a couple of types of URLs for local files
	$local_path = $local;
	if($local_path =~ m|^x-gass-cache://|)
	{
	    chomp($local_path = `$cache_pgm -query $local_path 2>/dev/null`);

	    if($local_path eq '')
	    {
		return Globus::GRAM::Error::STAGE_OUT_FAILED;
	    }
	}
	elsif($local_path =~ m|^file:/|)
	{
	    $local_path =~ s|^file:/+|/|;
	}
	if($local_path !~ m|^/|)
	{
	    $local_path = $description->directory() . '/' . $local;
	}

	if(system("$url_copy file://$local_path $remote >/dev/null 2>&1") != 0)
	{
	    return Globus::GRAM::Error::STAGE_OUT_FAILED;
	}
	$self->respond({'STAGED_OUT' => "$local $remote"});
    }
    return {};
}

=item $manager->cache_cleanup()

Clean up cache references in the GASS which match this job's cache tag .

=cut

sub cache_cleanup
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $tag = $description->cache_tag() or $ENV{GLOBUS_GRAM_JOB_CONTACT};

    system("$cache_pgm -cleanup-tag -t $tag > /dev/null 2>/dev/null");

    return {};
}

=item $manager->remote_io_file_create()

Create the remote I/O file in the GASS cache which will contain the
remote_io_url RSL attribute's value.

=cut

sub remote_io_file_create
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $tag = $description->cache_tag() or $ENV{GLOBUS_GRAM_JOB_CONTACT};
    my $filename = "${tag}dev/remote_io_url";
    my $tmpname = POSIX::tmpnam();
    my $tmpfile = new IO::File(">$tmpname");
    my $fh;
    my $result;

    $tmpfile->print($description->remote_io_url() . "\n");
    $tmpfile->close();

    system("$cache_pgm -add -t $tag -n $filename file:$tmpname >/dev/null");

    unlink($tmpname);

    if($? != 0)
    {
	return Globus::GRAM::Error::WRITING_REMOTE_IO_URL;
    }

    chomp($result = `$cache_pgm -query $filename`);

    if($? != 0)
    {
	return Globus::GRAM::Error::WRITING_REMOTE_IO_URL;
    }

    return { REMOTE_IO_FILE => $result };
}

=item $manager->proxy_relocate()

Relocate the delegated proxy for job execution. Job Managers need to
override the default if they intend to relocate the proxy into some
common file system other than the cache. The job manager program does
not depend on the new location of the proxy. Job Manager modules must
not remove the default proxy.

=cut

sub proxy_relocate
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $info_pgm = "$Globus::Core::Paths::bindir/grid-proxy-info";

    chomp($proxy_filename = `$info_pgm -path 2>/dev/null`);

    if($? != 0 || $proxy_filename eq "")
    {
	return Globus::GRAM::Error::OPENING_USER_PROXY;
    }

    $proxy_filename =~ s/^\S+\s+:\s+//;

    return { X509_USER_PROXY => $proxy_filename }
}

=item $hashref = $manager->proxy_update();

=cut

sub proxy_update
{
    return {};
}

=item $manager->append_path($ref, $var, $path)

Append $path to the value of $ref->{$var}, dealing with the case where
$ref->{$var} is not yet defined.

=cut

sub append_path
{
    my $self = shift;
    my $ref = shift;
    my $var = shift;
    my $path = shift;

    if(exists($ref->{$var}))
    {
	$ref->{$var} .= ":$path";
    }
    else
    {
	$ref->{$var} = "$path";
    }
}

1;

=back

=head1 RESPONSES

When returning from a job interface method, or when sending an intermediate
response via the I<response>() method, the following hash keys are valid:

=over 4

=item * JOB_STATE

An integer job state value. These are enumerated in the Globus::GRAM::JobState
module.

=item * ERROR

An integer error code. These are enumerated in the Globus::GRAM::Error module.

=item * JOB_ID

A string containing a job identifier, which can be used to poll, cancel, or
signal a job in progress. This response should only be returned by the
I<submit> method.

=item * SCRATCH_DIR

A string containing the path to a newly-created scratch directory. This
response should only be returned by the I<make_scratchdir> method.

=item * STAGED_IN

A string containing the (URL, path) pair for a file which has now been staged
in. This response should only be returned by the I<stage_in> method.

=item * STAGED_IN_SHARED

A string containing the (URL, path) pair for a file which has now been staged
in and symlinked from the cache. This response should only be returned by the
I<stage_in_shared> method.

=item * STAGED_OUT

A string containing the (path, URL) pair for a file which has now been staged
out by the script. This response should only be returned by the
I<stage_out> method.

=back

=cut
