BEGIN
{
    push(@INC, "$ENV{GLOBUS_LOCATION}" . '/lib/perl');
}

#use warnings;
use strict;
use Globus::Core::Paths;

# Prototypes
sub GassCacheList ( );
sub GassCacheCleanupUrl ( $ );
sub DumpHelp( );


# ******************************************************
# Command line options
# ******************************************************
my $PerlOperations =<<END_OPERATIONS;
    -cleanup-url   - remove all tags for an URL in the cache
                     This operation requires that the URL be specified on
                     the command line.
    -list          - list the contents of the cache.
                     If either the [-t tag] or a URL is specified on the
                     command line, then only cache entries which match
                     those will be listed
END_OPERATIONS
my $PerlOptions =<<END_OPTIONS;
END_OPTIONS

my $Program = $0;
my $ProgramC = $Globus::Core::Paths::libexecdir . '/globus-gass-cache-util';
my $Verbose = 0;


# Option flags
my $OptionLong = 0;

# C Program flags & args
my @CprogFlags = (
		  "-a", "-add",
		  "-d", "-delete",
		  "-dirs",
		  "-m", "-mangle",
		  "-q", "-query",
		  "-cleanup-tag",
		  );
my $CprogFlagsRE =
    "(" . join( ")|(", @CprogFlags ) . ")";

# C Program flags & args
my @CprogArgs = (
		 "-h", "-mdshost",
		 "-p", "-mdsport",
		 "-b", "-mdsbasedn",
		 "-T", "-mdstimeout",
		 "-r", "-resource",
		 "-n", "-newname",
		 "-t", "-tag" );
my $CprogArgsRE =
    "(" . join( ")|(", @CprogArgs ) . ")";

# Arguments that the "C" _doesn't_ understand, and need to be stripped
# off before we punt to the C program
my @CprogNonArgs = (
		    "-l", "-list",
		    "-cleanup-url",
		   );
my $CprogNonArgsRE =
    "(" . join( ")|(", @CprogNonArgs ) . ")";

# The manglings we know about..
my @Manglings = ( "html", "md5" );

# Make stdout sane
$|=1;

# Store the URL to process
my $URL = "";

# Empty command line; punt it
if ( $#ARGV < 0 )
{
    exec ( "$ProgramC", @ARGV );
}

# Build list of C program arguments..
my @CprogArgv = grep{!/^$CprogNonArgsRE$/} @ARGV;

# Help; punt + our own processing...
if ( grep( /^-help$/, @ARGV ) >= 1 )
{
    DumpHelp();
    exit 0;
}

# Walk through the command line
my @JobList;
my $ArgNo;
for($ArgNo = 0; $ArgNo < @ARGV; $ArgNo++)
{
    my $Arg = $ARGV[$ArgNo];

    if ( ( $Arg eq "-l" ) || ( $Arg eq "-list" ) )
    {
	push @JobList, "list";
    }
    elsif ( ( $Arg eq "-cu" ) || ( $Arg eq "-cleanup-url" ) )
    {
	push @JobList, "cleanup-url";
    }
    elsif ( $Arg eq "-long" )
    {
	$OptionLong = 1;
    }
    elsif ( ( $Arg eq "-v" ) || ( $Arg eq "-verbose" ) )
    {
	$Verbose++;
    }
    elsif ( $Arg =~ /^($CprogFlagsRE)$/ )
    {
	# Invoke the C program
	exec ( "$ProgramC", @CprogArgv );
    }
    elsif ( $Arg =~ /^($CprogArgsRE)$/ )
    {
	# Skip next arg...
        $ArgNo++;
    }
    elsif ( $Arg =~ /^-/ )
    {
	# Not sure what the hell it is, punt it off to the C prog...
	exec ( "$ProgramC", @CprogArgv );
    }
    # Must be the URL
    else
    {
	$URL = $Arg;
    }
}

# Did we do anything?  If not, punt to the C program...
if ( $#JobList < 0 )
{
    exec ( "$ProgramC", @CprogArgv );
}
else
{
    $#ARGV = -1;
    foreach my $Job ( @JobList )
    {
	if ( $Job eq "list" )
	{
	    GassCacheList( );
	}
	elsif ( $Job eq "cleanup-url" )
	{
	    GassCacheCleanupUrl( $URL );
	}
    }
}   # End of logical "main"
# ******************************************************

# ******************************************************
# Function: GassCacheList()
#
# Description:
#	List the contents of the Cache
#
# Parameters:
#  None
#
# Return Values:
#  None
#
# ******************************************************
sub GassCacheList ( )
{
    my %RootDirs;

    # Read the directories from the program...
    delete( $ENV{GLOBUS_GASS_CACHE_DEBUG} );
    my $Cmd = "$ProgramC -dirs";
    open( DIRS, "$Cmd|" ) || die "Can't run '$Cmd'";
    while( <DIRS> )
    {
	if ( /^(\w+)_ROOT: '(.*)'/ )
	{
	    $RootDirs{$1} = $2;
	}
    }
    close( DIRS );
    die "No GLOBAL root" if ( ! defined $RootDirs{GLOBAL} );
    die "No LOCAL root" if ( ! defined $RootDirs{LOCAL} );

    # *************************************************
    # Now, let's do the real fun...
    #  Scan through the global directory for all URLs
    # *************************************************
    print "Scanning the global entries in $RootDirs{GLOBAL}\n" if( $Verbose );
    my %Global;
    $Cmd = "find $RootDirs{GLOBAL} -name 'data*' -print";
    foreach my $FullPath (`$Cmd` )
    {
	chomp $FullPath;
	my @Stat = stat( $FullPath );
	my $Inode = $Stat[1];
	my $Size = $Stat[7];

	# And, let's get it's directory
	my @Dirs = split( /\//, $FullPath );
	$#Dirs--;
	my $Dir = join( "/", @Dirs );

	# Read the URL from the "url" file
	my $Url = "";
	if ( open( URL, "$Dir/url" ) )
	{
	    $Url = <URL>; chomp $Url;
	    close( URL );
	}

	# Pull out it's mangled dir
	my $Mangled = $Dir;
	$Mangled =~ s/$RootDirs{GLOBAL}\///;

	# Store it all in a (perl) hash
	my $r = ();
	$r->{Inode} = $Inode;
	$r->{Size} = $Size;
	$r->{Url} = $Url;
	$r->{Mangled} = $Mangled;
	$r->{Dir} = $Dir;
	$Global{$Inode} = $r;
	$r = ();
    }
    close( FIND );

    # ******************************************
    # Scan through the local directory, now..
    # ******************************************
    print "Scanning the local entries in $RootDirs{LOCAL}\n" if( $Verbose );
    my @Local;
    $Cmd = "find $RootDirs{LOCAL} -name 'data.*' -print";
    foreach my $FullPath (`$Cmd` )
    {
	chomp $FullPath;
	my @Stat = stat( $FullPath );
	my $Inode = $Stat[1];
	my $Size = $Stat[7];

	# Get the directory portion of the path
	my @Dirs = split( /\//, $FullPath );
	$#Dirs--;
	my $Dir = join( "/", @Dirs );

	# Read the tag from the tag file..
	my $Tag = "";
	if ( open( TAG, "$Dir/tag" ) )
	{
	    $Tag = <TAG>;
	    close( TAG );
	}

	# Strip the local dir portion off the hash
	my $Mangled = $Dir;
	$Mangled =~ s/$RootDirs{LOCAL}\///;

	# There *should* be a matching global... Let's look
	my $MangledOk = 0;
	if ( defined( $Global{$Inode} ) )
	{
	    my $GlobalMangled = $Global{$Inode}->{Mangled};
	    $Mangled =~ s/\/$GlobalMangled//;
	    $MangledOk = 1;
	}
	# Otherwise, we should be able to get the hash from the tag..
	elsif ( $Tag ne "" )
	{
	    my $Cmd = "$ProgramC -t $Tag -m";
	    if ( open ( MANGLE, "$Cmd|" ) )
	    {
		while( <MANGLE> )
		{
		    if ( /^TAG: '(.*)'/ )
		    {
			$Mangled = $1;
			$MangledOk = 1;
		    }
		}
		close( MANGLE );
	    }
	}

	# Otherwise, let's make some guesses..
	if ( ! $MangledOk )
	{
	    # Should currently be something like: md5/local/md5/global
	    foreach my $GlobalStr ( @Manglings )
	    {
		$GlobalStr = "/" . $GlobalStr . "/";
		my $GlobalStart = rindex( $Mangled, $GlobalStr );
		if ( $GlobalStart > 0 )
		{
		    $Mangled = substr( $Mangled, 0, $GlobalStart );
		    last;
		}
	    }
	}

	# Store it all in a (perl) hash
	my $r = ();
	$r->{Inode} = $Inode;
	$r->{Size} = $Size;
	$r->{Tag} = $Tag;
	$r->{Mangled} = $Mangled;
	$r->{Dir} = $Dir;
	push( @Local, $r );
	$r = ();
    }

    # ********************
    # Dump it all out..
    # ********************
    foreach my $Inode ( keys %Global )
    {
	print "URL: $Global{$Inode}->{Url}\n";
	if ( $OptionLong )
	{
	    print "\tSize: $Global{$Inode}->{Size}\n";
	    print "\tMangled: $Global{$Inode}->{Mangled}\n";
	}
	foreach my $Local ( @Local )
	{
	    if ( $Local->{Inode} == $Inode )
	    {
		print "\tTag:" . $Local->{Tag} . "\n";
	    }
	}
    }
}   # GassCacheList()


# ******************************************************
# Function: GassCacheCleanupUrl
#
# Description:
#	Cleanup a URL in the GASS Cache
#
# Parameters:
#  URL to cleanup
#
# Return Values:
#  None
#
# ******************************************************
sub GassCacheCleanupUrl ( $ )
{
    my $Url = shift;
    my %RootDirs;

    # Sanity check...
    if ( !defined( $Url ) || ( $Url eq "" )  )
    {
	print STDERR "CleanupUrl requires a URL to cleanup\n";
	DumpHelp( );
	exit 1;
    }

    # Mangle the URL
    delete( $ENV{GLOBUS_GASS_CACHE_DEBUG} );
    my $Mangled = "";
    {
	my $Cmd = "$ProgramC -mangle $Url";
	open( MANGLE, "$Cmd|" ) || die "Can't run '$Cmd'\n";
	while ( <MANGLE> )
	{
	    chomp;
	    if ( /URL:\s+\'(.*)\'/ )
	    {
		$Mangled = $1;
	    }
	}
	close( MANGLE );
	if ( $Mangled eq "" )
	{
	    print STDERR "Failed to mangle URL!\n";
	    exit 1;
	}
    }

    # Read the directories from the program...
    my $Cmd = "$ProgramC -dirs";
    open( DIRS, "$Cmd|" ) || die "Can't run '$Cmd'";
    while( <DIRS> )
    {
	if ( /^(\w+)_ROOT: '(.*)'/ )
	{
	    $RootDirs{$1} = $2;
	}
    }
    close( DIRS );

    # Let's learn all about our data file...
    my $FullGlobalDir = "$RootDirs{GLOBAL}/$Mangled";
    if ( ! -d $FullGlobalDir )
    {
	print STDERR "Could not clean up file because ".
	    "the URL was not found in the GASS cache.\n";
	exit 1;
    }
    my $FullGlobalData = "$FullGlobalDir/data";
    if ( ! -f $FullGlobalData )
    {
	print STDERR "Could not clean up file because ".
	    "the URL was not found in the GASS cache.\n";
	exit 1;
    }
    my $FullGlobalDataInode = -1;
    {
	my @Stat = stat( $FullGlobalData );
	if ( $#Stat < 0 )
	{
	    print STDERR "Could not stat data file for URL '$Url'\n";
	    print STDERR "Should be '$FullGlobalData'\n";
	    exit 1;
	}
	$FullGlobalDataInode = $Stat[1];
    }

    # Tell the user...
    print "Found global data file @ $FullGlobalData\n" if( $Verbose );

    # Scan through the local directory, now..
    my %Local;
    my $LocalCount = 0;
    $Cmd =
	"find $RootDirs{LOCAL} -inum $FullGlobalDataInode -print";
    open( FIND, "$Cmd|" ) || die "Can't run '$Cmd'";
    print "Scanning the local entries in $RootDirs{LOCAL}\n" if( $Verbose );
    while( <FIND> )
    {
	chomp;
	my $FullDataPath = $_;

	my @Dirs = split( /\//, $FullDataPath );
	my $DataFile = pop @Dirs;
	my $Dir = join( "/", @Dirs );
	die "Oops" if ( "$Dir/$DataFile" ne $FullDataPath );
	my $TagFile = "$Dir/tag";

	# Check it out..
	if ( ! -f $FullDataPath )
	{
	    print STDERR "$FullDataPath is not a file!\n";
	    next;
	}
	if ( ! ( $FullDataPath =~ /\/data/ ) )
	{
	    print STDERR "$FullDataPath is not a data file!!\n";
	    next;
	}
	if ( ! -d $Dir )
	{
	    print STDERR "$Dir is not a directory!!\n";
	    next;
	}
	my $Tag;
	if ( ! -f $TagFile )
	{
	    print STDERR "$TagFile <tag file> not found\n";
	    my $Tag = "";
	}
	else
	{
	    $Tag = `cat $TagFile`;
	}

	# Store it...
	my $r = {};
	$r->{Tag} = $Tag;
	$r->{File} = $DataFile;
	push @{$Local{$Dir}}, $r;
	$r = {};
	$LocalCount++;
    }
    close( FIND );

    # Print results to the user...
    if( $Verbose )
    {
	if ( $LocalCount <= 0 )
	{
	    print "No local links found\n";
	}
	else
	{
	    print "Found $LocalCount local links:\n";
	    foreach my $Dir ( keys %Local )
	    {
		foreach my $FileRec ( @{$Local{$Dir}} )
		{
		    my $File = $FileRec->{File};
		    my $Tag = $FileRec->{Tag};
		    if ( $Tag eq "" )
		    {
			print "\t$Dir/$File\n";
		    }
		    else
		    {
			print "\t$Tag\n";
		    }
		}
	    }
	}
    }

    # Clean it all up...
    foreach my $Dir ( keys %Local )
    {
	foreach my $FileRec ( @{$Local{$Dir}} )
	{
	    print "$FileRec->{Tag}.. ($FileRec->{File}) " if ( $Verbose );
	    unlink "$Dir/$FileRec->{File}";
	    print "\n" if ( $Verbose );
	}

	# Blow away the extras..
	unlink "$Dir/url";
	unlink "$Dir/tag";

	# Temp dir for working in..
	my $TmpDir;

	# Blow away the directories..
	my @Dirs = split( /\//, $Dir );
	while( 1 )
	{
	    $TmpDir = join ('/', @Dirs );
	    last if ( $TmpDir eq $RootDirs{LOCAL} );
	    last if ( ! rmdir( $TmpDir ) );
	    print "\t$TmpDir\n " if ( $Verbose );
	    pop @Dirs;
	}

	# Check: does this directory have only a "tag" file?
	my $TagFile = "$TmpDir/tag";
	if (  ( $TmpDir ne $RootDirs{LOCAL} ) && ( -f "$TagFile" )  )
	{
	    my @Stat = stat( "$TagFile" );

	    # Unlink it if it's the last one..
	    if ( $Stat[3] == 1 )
	    {
		unlink( "$TagFile" );
	    }

	    # Try cleaning up more...
	    while( 1 )
	    {
		$TmpDir = join ('/', @Dirs );
		last if ( $TmpDir eq $RootDirs{LOCAL} );
		last if ( ! rmdir( $TmpDir ) );
		print "\t$TmpDir\n " if ( $Verbose );
		pop @Dirs;
	    }
	}
    }

    # And, remove the global dir
    {
	my $Dir = $FullGlobalDir;
	print "Global.. " if ( $Verbose );
	unlink "$Dir/data";
	unlink "$Dir/url";

	my @Dirs = split( /\//, $Dir );
	while( 1 )
	{
	    my $TmpDir = join ('/', @Dirs );
	    last if ( $TmpDir eq $RootDirs{GLOBAL} );
	    last if ( ! rmdir( $TmpDir ) );
	    print "\n\t$TmpDir " if( $Verbose );
	    pop @Dirs;
	}
	print "\n" if ( $Verbose );
    }

}   # GassCacheCleanupUrl()

sub DumpHelp( )
{
    open( PROGC,  "$ProgramC -help 2>&1 |" )
	or die "Can't run '$ProgramC' for help";

    # Just print everything up 'til the "Valid optoins" line
    $_ = <PROGC>;
    while ( <PROGC> )
    {
	print;
	last if ( /^Valid oper/ );
    }

    # Now, all the C program operations..
    while ( <PROGC> )
    {
	chomp; s/\s+$//;
	last if ( $_ eq "" );
	print "$_\n";
    }

    # Print out _our_ operations
    print "$PerlOperations\n";

    # Now, all the C program options..
    while ( <PROGC> )
    {
	chomp; s/\s+$//;
	last if ( $_ eq "" );
	print "$_\n";
    }
    # Print out _our- options
    print "$PerlOptions\n";
    close( PROGC );
}
