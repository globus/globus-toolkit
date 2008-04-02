#! /usr/bin/env perl

################################################################################
#
# This scripts checks if audit logging works correctly in GRAM2.
# A personal gatekeeper is started and a job is submitted. Then
# tests are done if the audit-record was created by the job manager,
# if the record was inserted into the database and if the record-file
# is removed from disk after the insert.
#
# Flow:
#   1. Check if the directory that stores audit-records is configured
#      in the job manager configuration
#   2. Check if the database access information exists
#   3. success so far? => start audit-enabled personal gatekeeper with
#      information about audit configuration
#   4. Submit a job
#   5. Check if an audit-record file was created, that it contains exactely
#      one audit-record, that it contains the required number of fields (14)
#      and that those fields are not null that must be not null (database
#      schema)
#   6. Call the script that moves records to the database
#   7. Check that the audit-record file doesn't exist anymore
#
################################################################################

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

use strict;
use Test::Harness;
use Cwd;
require 5.005;
use vars qw(@tests);
use Globus::Core::Paths;

my $contact;          # contact string of the gatekeeper
my $startargs;        # start arguments of the gatekeeper
my $kill_gatekeeper;  # kill the gatekeeper at the end (1=yes,0=no)
my $test_result;      # return value of this script (0=success,1=failure)
my $db_info_file;     # contains information about database access values       
my $job_manager_conf; # read the location where audit records are stored from here
my $audit_data_dir;   # directory where the audit records are written into
my $rsl;              # job description of the job that's submitted 
my $field_separator;  # field separator of the fields in the audit record
my $database_script;  # script that merges the audit records to the database
my $log4j_file;       # contains information for the Java AuditDatabaseAppender
 
# initialize variables
$test_result = 0;
$kill_gatekeeper = 1;
$startargs = '-log never ';
$db_info_file = "$ENV{GLOBUS_LOCATION}/etc/globus-job-manager-audit.conf";
$job_manager_conf = "$ENV{GLOBUS_LOCATION}/etc/globus-job-manager.conf";
$database_script = "$ENV{GLOBUS_LOCATION}/libexec/globus-gram-audit";
$log4j_file = "";
$audit_data_dir = get_audit_dir();
$rsl = "&(executable=/bin/true)";
$field_separator = '","';

# check if an audit directory is configured
if ($audit_data_dir eq '')
{
  $kill_gatekeeper = 0;
  $test_result = 1;
  cleanup_and_exit("No audit record directory specified => no test");
}

# check that the audit directory exists
if (!-e $audit_data_dir)
{
  $kill_gatekeeper = 0;
  $test_result = 1;
  cleanup_and_exit("Audit record directory ".$audit_data_dir.
                   " does not exist");
}

# check that the database configuration exists
if (!-e $db_info_file)
{
  $test_result = 1;
  cleanup_and_exit(
      "Database information file $db_info_file doesn't exist");
}  

# append the audit directory location to the arguments for the
# globus-personal-gatekeeper
$startargs .= "-auditdir $audit_data_dir ";

if(0 != system("grid-proxy-info -exists -hours 2 2>/dev/null") / 255)
{
    $ENV{X509_CERT_DIR} = cwd();
    $ENV{X509_USER_PROXY} = "testcred.pem";
    system('chmod go-rw testcred.pem'); 
}


# Use a running gatekeeper if available.
# Otherwise: start a personal gatekeeper for testing purpose
if(exists($ENV{CONTACT_STRING}))
{
    print "Using gatekeeper at " . $ENV{CONTACT_STRING} . "\n";
    $kill_gatekeeper = 0;
}
else
{
    my $personal_gatekeeper = $Globus::Core::Paths::bindir
                               . "/globus-personal-gatekeeper";
    system("$personal_gatekeeper -killall >/dev/null 2>/dev/null");
    system("$personal_gatekeeper -start $startargs >/dev/null 2>/dev/null");
    chomp($contact = `$personal_gatekeeper -list`);

    if($? != 0)
    {
	print "Could not start gatekeeper\n";
	exit 1;
    }
    $ENV{CONTACT_STRING} = $contact;
    $kill_gatekeeper = 1;
}

# Submit a job in batch mode to get the job-id. This job-id contains strings
# that are used in the name of the corresponding audit record file. An audit
# record file with these strings is searched in the audit record directory.
# Since the job is submitted in batch mode and the audit record is written at
# the very end right before the job manager finishs: accept some wait time
# until the record file is written
my $output = `globusrun -s -b -r "$contact" "$rsl"`;
my @id_parts = split(/\//,$output);


# Check 60 seconds if the audit-record file that fits to the
# submitted job was created. If not assume that an error occured
my $found_flag = 0;
my @audit_files = ();
for (my $i=0; $i<60; $i++)
{
  # Check if an audit record file for that job was created
  @audit_files = glob("$audit_data_dir/*.gramaudit");

  # check if an audit record for the job was created
  # fields 3 and 4 in id_parts contain informations to find
  # the right audit record file
  for (my $i=0; $i<scalar(@audit_files); $i++)
  {
    if ($audit_files[$i] =~ /$id_parts[3]/ &&
        $audit_files[$i] =~ /$id_parts[4]/ &&
        $audit_files[$i] =~ ".gramaudit")
    {
       $found_flag = 1;
       last;
    }
  }
  
  if ($found_flag)
  {
     last;
  }
  else
  {
     sleep(1);
  } 
}

# if the audit-record file was not found
if (!$found_flag)
{
  $test_result = 1;
  cleanup_and_exit("No audit record file created by Gram ".
                   "(is it really configured?).");
   
}


# Read the the audit record file and check if it contains the right
# number of entries.
if (!open(AUDIT_FILE,"<@audit_files[0]"))
{
   $test_result = 1;
   cleanup_and_exit("Can't open audit record file");
}

my @audit_record = <AUDIT_FILE>;
close(AUDIT_FILE);

# Check that exactely one audit record is in there
if (scalar(@audit_record) != 1) 
{
   $test_result = 1;
   cleanup_and_exit("Audit record file contained more that one line");
}
my @audit_fields = split(/$field_separator/,$audit_record[0]);

# Check that the audit record contains exactely 15 fields
if (scalar(@audit_fields) != 15)
{
   $test_result = 1;
   cleanup_and_exit("Not exactely 15 fields in the audit record file");
}

# Check that those fields that must not be null (database schema) are not null.
# These are the fields subject_name(2), username(3), creation_time(5), 
# globus_toolkit_version(10), resource_manager_type(11), job_description(12),
# success_flag(13) and finished_flag(14)
my $null_field = "";
if (lc($audit_fields[2])  eq "null")
{ 
  $null_field = "subject_name";
}
elsif (lc($audit_fields[3])  eq "null")
{
  $null_field = "username";
}
elsif (lc($audit_fields[5])  eq "null")
{
  $null_field = "creation_time";
}
elsif (lc($audit_fields[10])  eq "null")
{
  $null_field = "globus_toolkit_version";
}
elsif (lc($audit_fields[11])  eq "null")
{
  $null_field = "resource_manager_type";
}
elsif (lc($audit_fields[12])  eq "null")
{
  $null_field = "job_description";
}
elsif (lc($audit_fields[13])  eq "null")
{
  $null_field = "success_flag";
}
elsif (lc($audit_fields[14])  eq "null")
{
  $null_field = "finished_flag";
}

if (! $null_field eq "")
{
   $test_result = 1;
   cleanup_and_exit("Field $null_field in audit record ".
                    "is null but must not be null");
}


# Call the script that merges the audit record to the database.
# Call it with an option so that the AuditDatabaseAppender checks
# itself if the insert of the record to the database was successful 
if (system("$database_script --check"))
{
   $test_result = 1;
   cleanup_and_exit("Script that moves audit-records ".
                    "to the database failed");
}


# Check that the audit record file has been removed. It could
# be that other audit record files had been created in the meantime
$found_flag = 0;
@audit_files = glob("$audit_data_dir/*.gramaudit");

for (my $i=0; $i<scalar(@audit_files); $i++)
{
  if ($audit_files[$i] =~ /$id_parts[3]/ &&
      $audit_files[$i] =~ /$id_parts[4]/ &&
      $audit_files[$i] =~ ".gramaudit")
  {
     $found_flag = 1;
     last;
  }
}
  
if ($found_flag)
{
   $test_result = 1;
   cleanup_and_exit("audit record file wasn't removed".
             " after the record had been inserted to the database");
}

# finally clean up at the end if everything worked ok
cleanup_and_exit();


############################ Helper methods ####################################

# reads the location where the audit records are stored
# from the configuration file $GLOBUS_LOCATION/etc/globus-job-manager.conf
sub get_audit_dir
{
    local(*F);
    my $audit_dir = '';

    if (!open(F, "<$job_manager_conf"))
    {
       $test_result = 1;
       cleanup_and_exit("Can't read job manager configuration file");
    }

    while(<F>)
    {
        if (m/-audit-directory\s+(\S+)\s+/)
        {
            $audit_dir = $1;
            $audit_dir =~ s/"//;
            last;
        }
    }
    close(F);

    return $audit_dir;
}


# stops and removes data of the personal gatekeeper and returns the
# success of the script (0=success, 1=failure)
sub cleanup_and_exit
{
    if($kill_gatekeeper)
    {
	system("globus-personal-gatekeeper ".
               "-kill \"$contact\" >/dev/null 2>&1");
    }
    if (!$test_result)
    {
        print STDOUT "ok\n";
    }
    else
    {
        my $error_string = shift;
        print STDOUT "failed: ".$error_string."\n";
    }
    exit $test_result;
}
