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
use Globus::GRAM::ExtensionsHandler;
use Globus::Core::Paths;

use POSIX;
use Errno;
use File::Path;
use File::Copy;

package Globus::GRAM::JobManager;

my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
my $url_copy_pgm = "$Globus::Core::Paths::bindir/globus-url-copy";
my $info_pgm = "$Globus::Core::Paths::bindir/grid-proxy-info";

=head1 NAME

Globus::GRAM::JobManager - Base class for all Job Manager scripts

=head1 SYNOPSIS

 $manager = new Globus::GRAM::JobManager($job_description);

 $manager->log("Starting new operation");
 $manager->nfssync($fileobj,$createflag);
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
 $scalar  = $manager->pipe_out_cmd(@arglist);
 ($stderr, $rc) = $manager->pipe_err_cmd(@arglist);
 $status  = $manager->fork_and_exec_cmd(@arglist);
 $manager->append_path($hash, $variable, $path);
 $scalar = $manager->setup_softenv();

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

    #parse the XML blob that is the extensions element in the job description
    if ($description->xml_extensions())
    {
        new Globus::GRAM::ExtensionsHandler($class, $description);
    }

    if(defined($description->logfile()))
    {
        local(*FH);
        open(FH, '>>'. $description->logfile());
        select((select(FH),$|=1)[$[]);
        $self->{log} = *FH;
    }

    bless $self, $class;

    $self->log("New Perl JobManager created.");
    eval { File::Path::mkpath($self->job_dir(), 0, 0700); };

    if ($@) {
        $self->log("Couldn't create job dir");
    }

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
        my $fh = $self->{log};
	print $fh scalar(localtime(time)), " JM_SCRIPT: ", @_, "\n";
    }

    return;
}

=item $manager->nfssync($object,$create)

Send an NFS update by touching the file (or directory) in question. If the
$create is true, a file will be created. If it is false, the $object will
not be created.

=cut

sub nfssync
{
    my $self = shift;
    my $object = shift;
    my $create_p = shift;

    my $now = time();
    unless ( utime( $now, $now, $object ) ) 
    {
        $self->log( "NFS sync for $object failed (may be harmless): $!" );

	# object did not exist
	if ( $create_p ) 
	{
	    local(*TEMP);
	    if ( open( TEMP, ">$object" ) ) {
                close(TEMP);
                $self->log( "NFS sync created $object" );
                utime($now, $now, $object) ||
                    $self->log( "NFS sync still unable to access $object" );
            } else {
                $self->log( "NFS sync could not create $object: $!" );
            }
	}
    }
    $self->log( "Sent NFS sync for $object" );
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
containing a scheduler-specific job identifier as the value of the hash's
JOB_ID key, and optionally, the a GRAM job state as the value of the hash's
JOB_STATE key if the job submission was successful;
otherwise a Globus::GRAM::Error value should be returned.
The job state values are defined in the Globus::GRAM::JobState module. The
job parameters (as found in the job rsl) are defined in
Globus::GRAM::Jobdescription object in $self->{JobDescription}.

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

    my $Loops = 0;
    while( (!$created) && ($Loops++ < 100) )
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
	    $self->nfssync( $dirname, 0 );
	    $self->log("I think it was made.... verifying");
	    if (-l $dirname || ! -d $dirname || ! -o $dirname)
	    {
		$self->log("nope, somebody's messing with us.");
		$created = 0;
	    }
	}
	elsif( $!{EEXIST} )
	{
	    $self->log("Already exist; trying again");
	}
	else
	{
	    last;
	}
    }

    # We give up
    if (!$created)
    {
	return Globus::GRAM::Error::INVALID_SCRATCH;
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
    if (!  defined $scratch_directory )
    {
	$self->log("Scratch directory not defined");
	return {};
    }
    $self->log("Removing $scratch_directory");
    chdir("/");
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
    my $tag = $description->cache_tag() || $ENV{'GLOBUS_GRAM_JOB_CONTACT'};
    my $url;
    my $filename;

    foreach ('stdin', 'executable')
    {
	chomp($url = $description->$_());
	if($url =~ m|^[a-zA-Z]+://|)
	{
	    my @arg = ($cache_pgm, '-query', '-t', $tag, $url);
            $filename = $self->pipe_out_cmd(@arg);
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
    my $tag = $description->cache_tag() || $ENV{'GLOBUS_GRAM_JOB_CONTACT'};
    my ($remote, $local, $local_resolved, $cached, $stderr, $rc, @arg);

    $self->log("stage_in(enter)");

    if($description->executable() =~ m|^[a-zA-Z]+://|)
    {
        @arg = ($cache_pgm, '-add', '-t', $tag, $description->executable());

        ($stderr, $rc) = $self->pipe_err_cmd(@arg);

        if ($rc != 0) {
            $self->log("executable staging failed with $stderr");

            $self->respond( {
                'GT3_FAILURE_TYPE' => 'executable',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $description->executable()
            });

            return Globus::GRAM::Error::STAGING_EXECUTABLE;
        }
        $local = $self->pipe_out_cmd($cache_pgm, '-q', '-t', $tag,
                $description->executable());
        if ($local eq '') {
            $self->respond( {
                'GT3_FAILURE_TYPE' => 'executable',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $description->executable()
            });

            return Globus::GRAM::Error::STAGING_EXECUTABLE;
        }
        $self->nfssync($local, 0);
    }
    if($description->stdin() =~ m|^[a-zA-Z]+://|)
    {
        @arg = ($cache_pgm, '-add', '-t', $tag, $description->stdin());
        ($stderr, $rc) = $self->pipe_err_cmd(@arg);

        if ($rc != 0) {
            $self->log("stdin staging failed with $stderr");

            $self->respond( {
                'GT3_FAILURE_TYPE' => 'stdin',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $description->stdin()
            });

            return Globus::GRAM::Error::STAGING_STDIN
        }
        $local = $self->pipe_out_cmd($cache_pgm, '-q', '-t', $tag,
                $description->stdin());
        if ($local eq '') {
            $self->respond( {
                'GT3_FAILURE_TYPE' => 'stdin',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $description->stdin()
            });

            return Globus::GRAM::Error::STAGING_STDIN;
        }
        $self->nfssync($local, 0);
    }
    foreach ($description->file_stage_in())
    {
        next unless defined $_;

	($remote, $local) = ($_->[0], $_->[1]);

	if($local !~ m|^/|)
	{
	    $local_resolved = $description->directory() . '/' . $local;
	}
        else
        {
            $local_resolved = $local;
        }

        @arg = ($url_copy_pgm, $remote, 'file://' . $local_resolved);

        ($stderr, $rc) = $self->pipe_err_cmd(@arg);
        if($rc != 0) {
            $self->log("filestagein staging failed with $stderr");

            $self->respond( {
                'GT3_FAILURE_TYPE' => 'filestagein',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $remote,
                'GT3_FAILURE_DESTINATION' => $local
            });
            return Globus::GRAM::Error::STAGE_IN_FAILED
        }
        $self->nfssync($local_resolved, 0);
	$self->respond({'STAGED_IN' => "$remote $local"});
    }
    foreach($description->file_stage_in_shared())
    {
        next unless defined $_;

	($remote, $local) = ($_->[0], $_->[1]);

	if($local !~ m|^/|)
	{
	    $local_resolved = $description->directory() . '/' . $local;
	}
        else
        {
            $local_resolved = $local;
        }

        @arg = ($cache_pgm, '-add', '-t', $tag, $remote);

        ($stderr, $rc) = $self->pipe_err_cmd(@arg);
        if($rc != 0) {
            $self->log("filestagein staging failed with $stderr");

            $self->respond( {
                'GT3_FAILURE_TYPE' => 'filestagein',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $remote,
                'GT3_FAILURE_DESTINATION' => $local
            });
            return Globus::GRAM::Error::STAGE_IN_FAILED
        }

        @arg = ($cache_pgm, '-query', '-t', $tag, $remote);
        $cached = $self->pipe_out_cmd(@arg);

        return Globus::GRAM::Error::STAGE_IN_FAILED
            if($cached eq '');

        symlink($cached, $local_resolved);

	$self->respond({'STAGED_IN_SHARED' => "$remote $local"});

	$self->log( "local=$local" );
	$self->log( "local_resolved=$local_resolved" );
	$self->nfssync( $local_resolved, 0 );
    }
    $self->log("stage_in(exit)");
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
    my $url_copy = "$Globus::Core::Paths::bindir/globus-url-copy";
    my $tag = $description->cache_tag() || $ENV{'GLOBUS_GRAM_JOB_CONTACT'};
    my $local_path;
    my @arg;

    $self->log("stage_out(enter)");

    $self->nfssync( $description->stdout(), 0 )
	if defined $description->stdout();
    $self->nfssync( $description->stderr(), 0 )
	if defined $description->stderr();

    foreach ($description->file_stage_out())
    {
        next unless defined $_;

	($local, $remote) = ($_->[0], $_->[1]);

	# handle a couple of types of URLs for local files
	$local_path = $local;
	if($local_path =~ m|^x-gass-cache://|)
	{
            @arg = ($cache_pgm, '-query', '-t', $tag, $local_path);
            $local_path = $self->pipe_out_cmd(@arg);

            return Globus::GRAM::Error::STAGE_OUT_FAILED
                if($local_path eq '');
	}
	elsif($local_path =~ m|^file:/|)
	{
	    $local_path =~ s|^file:/+|/|;
	}
	if($local_path !~ m|^/|)
	{
	    $local_path = $description->directory() . '/' . $local;
	}

        $self->nfssync($local_path, 0);
        @arg = ($url_copy_pgm, 'file://' . $local_path, $remote);

        ($stderr, $rc) = $self->pipe_err_cmd(@arg);
        if($rc != 0) {
            $self->log("filestageout staging failed with $stderr");

            $self->respond( {
                'GT3_FAILURE_TYPE' => 'filestageout',
                'GT3_FAILURE_MESSAGE' => $stderr,
                'GT3_FAILURE_SOURCE' => $local,
                'GT3_FAILURE_DESTINATION' => $remote
            });
            return Globus::GRAM::Error::STAGE_OUT_FAILED
        }

	$self->respond({'STAGED_OUT' => "$local $remote"});
    }
    $self->log("stage_out(exit)");
    return {};
}

=item $manager->cache_cleanup()

Clean up cache references in the GASS which match this job's cache tag .

=cut

sub cache_cleanup
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $tag = $description->cache_tag() || $ENV{'GLOBUS_GRAM_JOB_CONTACT'};
    my $job_path = $self->job_dir();

    $self->log("cache_cleanup(enter)");

    if ( defined $tag )
    {
         ($stderr, $rc) = $self->pipe_err_cmd($cache_pgm,
             '-cleanup-tag', '-t', $tag);
    }

    $self->log("Cleaning files in job dir $job_path");
    chdir("/");
    my $count = File::Path::rmtree($job_path);

    $self->log("Removed $count files from $job_path");

    if ($rc != 0) {
        $self->log("cache cleanup failed with $stderr");
    }

    $self->log("cache_cleanup(exit)");
    return {};
}

=item $manager->remote_io_file_create()

Create the remote I/O file in the job dir which will contain the
remote_io_url RSL attribute's value.

=cut

sub remote_io_file_create
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $tag = $description->cache_tag() || $ENV{'GLOBUS_GRAM_JOB_CONTACT'};
    my $job_path = $self->job_dir();
    my $filename = "$job_path/remote_io_url";

    $self->log("remote_io_file_create(enter)");

    local(*FH);

    open(FH, ">$filename");
    print FH $description->remote_io_url . "\n";
    close(FH);

    $self->nfssync($filename, 0);

    $self->log("remote_io_file_create(exit)");
    return { REMOTE_IO_FILE => $filename };
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
    my $proxy_filename;
    my $proxy_data;
    my $new_proxy;

    $self->log("proxy_relocate(enter)");

    $proxy_filename = $self->pipe_out_cmd($info_pgm, '-path');
    return Globus::GRAM::Error::OPENING_USER_PROXY
        if ( $? != 0 || $proxy_filename eq '' );

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

=item $manager->pipe_out_cmd(@arg)

Create a new process to run the first argument application with the 
remaining arguments (which may be empty). No shell metacharacter will
be evaluated, avoiding a shell invocation. Stderr is redirected to 
/dev/null and stdout is being captured by the parent process, which
is also the result returned.  In list mode, all lines are
returned, in scalar mode, only the first line is being returned. The
line termination character is already cut off. Use this function as
more efficient backticks, if you do not need shell metacharacter
evaluation.

Caution: This function deviates in two manners from regular backticks.
Firstly, it chomps the line terminator from the output. Secondly, it
returns only the first line in scalar context instead of a multiline
concatinated string. As with regular backticks, the result may be
undefined in scalar context, if no result exists.

A child error code with an exit code of 127 indicates that the application
could not be run. The scalar result returned by this function is usually
undef'ed in this case.

=cut

sub pipe_out_cmd
{
    my $self = shift;
    my @result;
    local(*READ);

    my $pid = open( READ, "-|" );
    return undef unless defined $pid;

    if ( $pid )
    {
        # parent
        chomp(@result = <READ>);
        close(READ);
    } else {
        # child
        open( STDERR, '>>/dev/null' );
        select(STDERR); $|=1;
        select(STDOUT); $|=1;
        if (!  exec { $_[0] } @_ )
        {
            exit(127);
        }
    }
    wantarray ? @result : $result[0];
}

=item ($stder, $rc) = $manager->pipe_err_cmd(@arg)

Create a new process to run the first argument application with the 
remaining arguments (which may be empty). No shell metacharacter will
be evaluated, avoiding a shell invocation.

This method returns a list of two items, the standard error of the program, and
the exit code of the program.  If the error code is 127, then the application
could not be run.  Standard output is discarded.

=cut

sub pipe_err_cmd
{
    my $self = shift;
    my $result;
    local(*READ);

    my $pid = open( READ, "-|" );

    return ("Error " . $! . " forking sub-process", -1) unless defined($pid);

    if ( $pid )
    {
        # parent
        chomp($result = scalar <READ>);
        close(READ);
    } else {
        # child
        open( STDERR, '>&STDOUT');
        open( STDOUT, '>>/dev/null' );
        select(STDERR); $|=1;
        select(STDOUT); $|=1;
        if (!  exec { $_[0] } @_ )
        {
            exit(127);
        }
    }
    ($result, $?);
}

=item $manager->fork_and_exec_cmd(@arg)

Fork off a child to run the first argument in the list. Remaining arguments
will be passed, but shell interpolation is avoided. Signals SIGINT and
SIGQUIT are ignored in the child process. Stdout is appended to /dev/null,
and stderr is dup2 from stdout. The parent waits for the child to finish,
and returns the value for the CHILD_ERROR variable as result. Use this
function as more efficient system() call, if you can do not need shell
metacharacter evaluation.

Note that the inability to execute the program will result in a status code
of 127.

=cut

sub fork_and_exec_cmd
{
    my $self = shift;
    my $pid = fork();

    return undef unless defined $pid;
    if ( $pid == 0 )
    {
       # child
       $SIG{INT} = 'IGNORE';
       $SIG{QUIT} = 'IGNORE';
       # FIXME: what about blocking SIGCHLD?
       open STDOUT, '>>/dev/null';
       open STDERR, '>&STDOUT'; # dup2()
       exec { $_[0] } @_;
       exit 127;
    }

    # parent
    waitpid($pid,0);   # FIXME: deal with EINTR and EAGAIN
    $?;
}

=item $manager->job_dir()

Return the temporary directory to store job-related files, which have no
need for file caching.

=cut

sub job_dir {
    my $self = shift;
    my $description = $self->{JobDescription};
    my $posix_hostname;
    my $job_dir = $description->job_dir();
    
    if ($job_dir ne '') {
        $self->log("Using jm supplied job dir: $job_dir");
        return $job_dir;
    } elsif (exists $ENV{GLOBUS_HOSTNAME}) {
        $posix_hostname = $ENV{GLOBUS_HOSTNAME};
    } else {
        $posix_hostname = (POSIX::uname)[1];

        if ($posix_hostname !~ m/\./) {
            my $aliases = join(' ',(gethostbyname($posix_hostname))[0,1]);

            for $alias (split(/\s+/, $aliases)) {
                if ($alias =~ m/\./) {
                    $posix_hostname = $alias;

                    last;
                }
            }
        }
    }

    $job_dir = $ENV{HOME}."/.globus/job/$posix_hostname/".$description->uniq_id();
    $self->log("making my own job dir @ $job_dir");

    return $job_dir;

}

=item $manager->setup_softenv()

Either add a line to the specified command script file handle to load the user's
default SoftEnv configuration, or create a custom SoftEnv script and
add commands to the specified command script file handle to load it.

=cut

sub setup_softenv
{
    my $self = shift;
    my $softenv_script_name = shift;
    my $soft_msc = shift;
    my $softenv_load = shift;
    my $job_script_fh = shift;

    my $description = $self->{JobDescription};

    my @softenv = $description->softenv();
    my $enable_default_software_environment
        = $description->enable_default_software_environment();
    if ((not @softenv) && (not $enable_default_software_environment))
    {
        return 0;
    }

    if ((not @softenv) && $enable_default_software_environment)
    {
        $self->log("default software environment requested");

        #load default software environment
        print $job_script_fh ". $softenv_load\n";
    }
    else
    {
        $self->log("custom software environment requested");

        local(*SOFTENV);
        open(SOFTENV, '>' . $softenv_script_name);

        foreach my $softenv (@softenv)
        {
            print SOFTENV $softenv . "\n";
        }

        close(SOFTENV);

        print $job_script_fh "$soft_msc $softenv_script_name\n";
        print $job_script_fh ". $softenv_script_name.cache.sh\n";
        print $job_script_fh "rm $softenv_script_name"
                           . " $softenv_script_name.cache.sh\n";
    }

    return 1;
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
