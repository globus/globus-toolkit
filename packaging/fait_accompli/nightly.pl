#!/usr/bin/env perl

use strict;
use DBI;
use LWP::UserAgent;
use Getopt::Long;
use HTTP::Request::Common qw(POST);

my $database="globusbld";
my $user="globus";
my $dbhost="right.mcs.anl.gov";
my $build_table="build";
my $test_table="tests";
my $pass="globustst";
my $dbh;  # database handle

my $UPLOAD_URL="http://www-unix.mcs.anl.gov/~bacon/cgi-bin/upload.pl";
my $NIGHTLY_ROOT="/home/bacon/builds/";
my $PACKAGING="/home/bacon/builds/packaging";
my $TESTING_ROOT="/home/bacon/tests/packaging";
my $GLOBUS_LOCATION="/sandbox/nightly-build";
$ENV{'GLOBUS_LOCATION'}=$GLOBUS_LOCATION;
$ENV{'GPT_LOCATION'}=$PACKAGING . "/gpt-3.0.1";
my $CVSROOT = ":pserver:anonymous\@cvs.globus.org:/home/globdev/CVS/gridservices";

my $LOG_LOCATION=$PACKAGING . "/build.log";
my $POSTINSTALL_LOG=$PACKAGING . "/postinstall.log";

#GT2 and GT3 tags
my ($t2,$t3) = ("globus_3_2_branch", "globus_3_2_branch");

my ($install, $report, $test) = (1, 1, 1);
GetOptions( 'i|install!' => \$install,
	    'r|report!' => \$report,
	    't2=s' => \$t2,
	    't3=s' => \$t3,
	    't|test!' => \$test
          ) or die "Unknown options";

# Unique build ID, main DB key.
my $id;

# Identify this machine, and what arch/os it currently is.
my ($machineid, $platformid);

my $verbose=0;

# main()

if ( $install )
{
    print "Cleaning up old build\n";
    system("/usr/bin/sudo /home/bacon/nightly-cleanup.sh");
    system("rm $LOG_LOCATION");
}

connect_to_db();
get_machine_id();

if ( $report )
{
    print "Creating new build\n";
    create_new_build();
}

print "Setting up env\n";
setup_environment_prebuild();

if ( $install )
{
    print "Running build\n";
    checkout_packaging();
    run_build();
    postinstall();
    print "ant setup\n";
    ant_setup();
    print "setperms\n";
    setperms();

    print "Building core tests\n";
    build_core_tests();
}

setup_environment_postbuild();

if ( $test )
{
    print "Running tests\n";
    run_perl_tests();

    print "Running core tests\n";
    run_core_tests();

    print "mjs tests\n";
    mjs_tests();
}

print "All done!\n";
exit;


#-------------------------------------------------------------------------------
sub setup_environment_postbuild()
#-------------------------------------------------------------------------------
{
    $ENV{'LD_LIBRARY_PATH'} = "$GLOBUS_LOCATION/lib:" . $ENV{'LD_LIBRARY_PATH'};
    $ENV{'PATH'} = "$GLOBUS_LOCATION/sbin:$GLOBUS_LOCATION/bin:" . $ENV{'PATH'};
}

#-------------------------------------------------------------------------------
sub connect_to_db()
#-------------------------------------------------------------------------------
{
   $dbh = DBI->connect("DBI:mysql:database=$database;host=$dbhost", $user, $pass) 
	|| die "Could not connect to DB $database on $dbhost as $user: $!\n";

   print "Connected to database!\n";
}

#-------------------------------------------------------------------------------
sub get_machine_id()
#-------------------------------------------------------------------------------
{
    my $sth = $dbh->prepare("SELECT * FROM machines WHERE hostname=" . $dbh->quote(`hostname`) . ";");
    $sth->execute();

    while (my $ref = $sth->fetchrow_hashref() )
    {
        $machineid = $ref->{'id'};
        $platformid = $ref->{'platform_id'};
    }
    $sth->finish();

}

# build:
# id, gt2tag, gt3tag, status, start, end, machine
# int, char,  char,   enum,   datetime, datetime, id
# An "id" of NULL autogenerates a new unique id, which we
# fetch back using the "mysql_insertid" feature.
#-------------------------------------------------------------------------------
sub create_new_build()
#-------------------------------------------------------------------------------
{
   my $now = time();

   $dbh->do("INSERT INTO build VALUES (NULL," . $dbh->quote($t2) . "," . $dbh->quote($t3) . "," . $dbh->quote("building") . ", NOW(), NULL, $machineid )" ) || die "Could not insert into $build_table: $!\n";

   $id = $dbh->{'mysql_insertid'};

   print "Inserted ID: $id\n";
}

#-------------------------------------------------------------------------------
sub setup_environment_prebuild()
#-------------------------------------------------------------------------------
{
   my $sth = $dbh->prepare("SELECT * FROM environment WHERE machine_id=$machineid");
   $sth->execute();

   while (my $ref = $sth->fetchrow_hashref() )
   {
        if ($ref->{'add_type'} eq "set")
        {
            $ENV{$ref->{'env_var'}} = $ref->{'env_value'};
        } elsif ($ref->{'add_type'} eq "prefix") {
	    $ENV{$ref->{'env_var'}} = $ref->{'env_value'} . $ENV{$ref->{'env_var'}};
        } elsif ($ref->{'add_type'} eq "postfix") {
	    $ENV{$ref->{'env_var'}} .= $ref->{'env_value'};
        }
   }
       
}
#-------------------------------------------------------------------------------
sub checkout_packaging()
#-------------------------------------------------------------------------------
{
    chdir $NIGHTLY_ROOT;
    system("cvs -d $CVSROOT co packaging");
}

#-------------------------------------------------------------------------------
sub run_build()
#-------------------------------------------------------------------------------
{
    chdir $PACKAGING;
    log_system("./make-packages.pl -t2=$t2 -t3=$t3 --anonymous --paranoia --bundles='gt3-all-src,globus-data-management-server,globus-data-management-client,globus-data-management-sdk,globus-resource-management-server,globus-resource-management-client,globus-resource-management-sdk,ogsi-cbindings,gt3-extras,mmjfs,mmjfs-static,scheduler-fork,all-test' --install=$GLOBUS_LOCATION", $LOG_LOCATION); 

    if ( $? eq 0)
    {
	report_build("success");
    } else {
	report_build("failure");
    }

    upload_log(`basename $LOG_LOCATION`);
}

# --------------------------------------------------------------------
sub upload_log
# --------------------------------------------------------------------
{
    my ($filename) = @_;

    return if not $report;

    my $ua = LWP::UserAgent->new;

    my $res=$ua->request(POST $UPLOAD_URL,
        Content_Type => 'multipart/form-data',
        Content => [ upload => ["$filename"], 
                     id => "$id",
        ]);

    if ($res->is_success) { 
        print "Uploading log successful.\n";
	print $res->as_string;
        print "\n";
    } else { 
        print "Uploading log unsuccessful.\n";
	print res->as_string;
        print "\n";
    }
}

# --------------------------------------------------------------------
sub report_build
# --------------------------------------------------------------------
{
    my ($status) = @_;

    return if not $report;
    $dbh->do("UPDATE $build_table SET status=" . $dbh->quote($status) . " WHERE id=$id");
    $dbh->do("UPDATE $build_table SET end=NOW() WHERE id=$id");
}

# --------------------------------------------------------------------
sub postinstall()
# --------------------------------------------------------------------
{
    log_system("$ENV{'GPT_LOCATION'}/sbin/gpt-postinstall", $POSTINSTALL_LOG);

    if ( $? eq 0 ) 
    {
        report_test("Postinstall", "success");
    } else {
        report_test("Postinstall", "failure");
    }

    upload_log(`basename $POSTINSTALL_LOG`);
}

#TODO:  Figure out how to insert/update this so I can start with "testing"
#  then change to success/failure afterwards.
# --------------------------------------------------------------------
sub report_test
# --------------------------------------------------------------------
{
    my ($test, $status) = @_;
    my ($sth, $testid);

    return if not $report;

    $sth = $dbh->prepare("SELECT * FROM test_defs WHERE test_name=" . $dbh->quote($test) . ";");
    $sth->execute();

    while (my $ref = $sth->fetchrow_hashref() )
    {
        $testid = $ref->{'test_id'};
    }
    $sth->finish();

    $dbh->do("INSERT INTO $test_table VALUES ($id, $testid, " . $dbh->quote($status) . ")" ) || die "Could not insert into $test_table: $!\n";
}

#-------------------------------------------------------------------------------
sub run_perl_tests()
#-------------------------------------------------------------------------------
{
    my $sth;

    print "Preparing query\n";
    $sth = $dbh->prepare("SELECT * FROM test_defs WHERE test_type=" . $dbh->quote('perl') . ";");
    print "Executing query\n";
    $sth->execute();
    print "Done executing\n";

    while (my $ref = $sth->fetchrow_hashref() )
    {
        perl_run_single($ref->{'test_name'}, $ref->{'test_dir'}, $ref->{'test_output'});
    }
    $sth->finish();
}

#-------------------------------------------------------------------------------
sub perl_run_single
#-------------------------------------------------------------------------------
{
    my ($name, $dir, $log) = @_;

    print "Running $name in $dir logging to $log\n";
    chdir "$GLOBUS_LOCATION/test/$dir";

    log_system("./TESTS.pl", "$log");

    if ( $? eq 0 ) 
    {
        report_test("$name", "success");
    } else {
        report_test("$name", "failure");
    }
    
    upload_log("$log");
}

#-------------------------------------------------------------------------------
sub build_core_tests()
#-------------------------------------------------------------------------------
{
    my $LOG = "$TESTING_ROOT/core-tests.log";

    chdir "$TESTING_ROOT";
    log_system("./make-packages.pl -t3=$t3 --anonymous --trees=gt3 --packages=core", $LOG);
    chdir "source-output/core-src";
    log_system("ant -f impl/java/build.xml buildUnitTest", $LOG);
}


#-------------------------------------------------------------------------------
sub run_core_tests()
#-------------------------------------------------------------------------------
{
    my $LOG = "$TESTING_ROOT/core-tests.log";
    chdir "$TESTING_ROOT/source-output/core-src/impl/java";

    log_system("source $GLOBUS_LOCATION/etc/globus-user-env.sh ; grid-proxy-init -cert ~/usercert.pem -key ~/userkey.pem", $LOG);

    log_system("ant testAll", "core-unit.log");

    if ( $? eq 0 ) 
    {
        report_test("Core Unit Test", "success");
    } else {
        report_test("Core Unit Test", "failure");
    }
    
    upload_log("core-unit.log");
}

# --------------------------------------------------------------------
sub setperms()
# --------------------------------------------------------------------
{
    log_system("/usr/bin/sudo $GLOBUS_LOCATION" . "/bin/setperms.sh", $LOG_LOCATION);
}

# --------------------------------------------------------------------
sub ant_setup()
# --------------------------------------------------------------------
{
    chdir $GLOBUS_LOCATION;
    log_system("ant setup", "setup.log");
    chdir $TESTING_ROOT;
}

# --------------------------------------------------------------------
sub mjs_tests()
# --------------------------------------------------------------------
{
    my $MJS_LOG="mjs.html";

    chdir $GLOBUS_LOCATION;
    system("nohup bin/globus-start-container > container.log &");
    # How to retrieve PID?
    chdir $TESTING_ROOT;
    chdir "source-output/core-src/impl/java/lib";
    
    system("cp $GLOBUS_LOCATION/lib/grim.jar .");
    system("$GLOBUS_LOCATION/bin/grid-proxy-init -cert /home/bacon/usercert.pem -key /home/bacon/userkey.pem");

    chdir $PACKAGING;
    chdir "bundle-output/BUILD/mjs-src";

    system("rm -f $MJS_LOG");
    log_system("ant testMjs -Dogsa.root=/home/bacon/tests/packaging/source-output/core-src/impl/java -Dtest.server.url=http://", `hostname`, ":8080/ogsa/services/", "$MJS_LOG");

    my $res = system("grep FAILED $MJS_LOG");
    if ( $res != 0 )
    {
        report_test("mjsJunit", "success");
    } else {
        report_test("mjsJunit", "failure");
    }

    log_system("ant testReport", "$MJS_LOG");
    foreach my $f (<test-reports/*>)
    {
        upload_log("$f");
    }
}

# --------------------------------------------------------------------
sub log_system
# --------------------------------------------------------------------
{
    my ($command, $log) = @_;

    my $output;
    my $res;

    if ( $verbose )
    {
        # This contruction is like piping through tee
        # except that I can get the return code too.
        open LOG, ">>$log";
        open FOO, "$command 2>&1 |";

        while (<FOO>)
        {
            my $line = $_;
            print $line;
            print LOG "$line";

        }

        close FOO;
        close LOG;
        $res = $?;
    }
    else
    {
        $output =  ">> $log 2>&1";
        system("$command $output");
        $res = $?
    }

    return $res;
}

