use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobManager;

package Globus::GRAM::JobManager::fork;

@ISA = qw(Globus::GRAM::JobManager);

my ($mpirun);

BEGIN
{
    $mpirun = '';
}

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    
    bless $self, $class;
    return $self;
}

sub submit
{
    my $self = shift;
    my $cmd;
    my $pid;
    my $job_id;
    my $count;
    my $multi_output = 0;
    my $tag = "$ENV{GLOBUS_GRAM_JOB_CONTACT}";
    my $format = "x-gass-cache://$tag/dev/std%s/%03d";
    my $cache_pgm = "$ENV{GLOBUS_LOCATION}/bin/globus-gass-cache";
    my $description = $self->{JobDescription};
    
    chdir $description->directory() or
        return Globus::GRAM::Error::INVALID_DIRECTORY;

    foreach $tuple ($description->environment())
    {
	$CHILD_ENV{@{$tuple}[0]} = @{$tuple}[1];
    }

    if($description->jobtype() eq "multiple")
    {
	$count = $description->count();
	$multi_output = 1 if $count > 1;
    }
    elsif($description->jobtype() eq "single")
    {
	$count = 1;
    }
    else
    {
        return Globus::GRAM::Error::JOBTYPE_NOT_SUPPORTED;
    }

    for(my $i = 0; $i < $count; $i++)
    {
	if($multi_output)
	{
	    my $out_name = sprintf($format, 'out', $i);
	    my $err_name = sprintf($format, 'err', $i);

	    system("$cache_pgm -add -n $out_name -t $tag file:/dev/null");
	    system("$cache_pgm -add -n $err_name -t $tag file:/dev/null");

	    $job_stdout = `$cache_pgm -query $out_name`;
	    $job_stderr = `$cache_pgm -query $err_name`;
	}
	else
	{
	    $job_stdout = $description->stdout();
	    $job_stderr = $description->stderr();
	}

	$pid = fork();

	if($pid == 0)
	{
            # forked child
	    %ENV = %CHILD_ENV;

	    close(STDIN);
	    close(STDOUT);
	    close(STDERR);

	    open(STDIN, "<" . $description->stdin());
	    open(STDOUT, ">>$job_stdout");
	    open(STDERR, ">>$job_stderr");

	    if(defined($description->arguments()))
	    {
		exec ($description->executable(),
		      $description->arguments())
		    || die "Error starting program";
	    }
	    else
	    {
		exec ($description->executable())
		    || die "Error starting program";
	    }
	}
	else
	{
	    $job_id .= ",$pid";
	}
    }
    # remove leading comma from pid list
    $job_id =~ s/^,//;
    $description->add('JobId', $job_id);
    return {(job_state => Globus::GRAM::JobState::ACTIVE,
            JOB_ID => $job_id)};
}

sub poll
{
    my $self = shift;
    my $description = $self->{JobDescription};

    $self->log("polling job $description->{JobId}");
    $_ = kill(0, split(/,/, $description->{JobId}));

    if($_ > 0)
    {
	return {(job_state => Globus::GRAM::JobState::ACTIVE)};
    }
    else
    {
	return {(job_state => Globus::GRAM::JobState::DONE)};
    }
}

sub rm
{
    my $self = shift;

    $self->log("rm job $self->{JobID}");

    kill(SIGTERM, split(/,/, $self->{grami_job_id}));

    sleep(5);
    
    kill(SIGKILL, split(/,/, $self->{grami_job_id}));

    return 0;
}

1;
