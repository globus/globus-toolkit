#!/usr/bin/env perl

use strict;
use Getopt::Long;

my $GL = $ENV{'GLOBUS_LOCATION'};
my $LD = $ENV{'LD_LIBRARY_PATH'};
my $simplecahash;
my $passwd;
my $yes;
my $rc;
my $hostname;
my $help;

GetOptions( 'y!' => \$yes,
            'pass=s' => \$passwd,
            'help|h' => \$help);

if ($help)
{
   print "Usage:\n";
   print "$0 -y [-pass=<pass>] [-help]\n";
   print "   -y: Confirm script execution.  Required.\n";
   print "   -pass: Supply a password.  ~/.globus/.simplecapass will\n";
   print "          be used if it exists.  If the file does not exist\n";
   print "          and a password is not supplied, the script will prompt\n";
   print "          for a password.  The password must be four or more characters\n";
   print "   -help: Display this help message.\n";
   exit 0;
}

if(!$yes)
{
    print "This script will destroy any hostcerts you may have in\n";
    print "\$GLOBUS_LOCATION/etc.  If this is ok, \n";
    print "then run with the -y option.\n";

    exit 8;
}

if ( $GL )
{
    print "Setting up $GL\n";
    $ENV{'PATH'} = "$GL/bin:$ENV{'PATH'}";
    if ( $LD )
    {
        $ENV{'LD_LIBRARY_PATH'} = "$GL/lib:$LD";
    }
    else
    {
        $ENV{'LD_LIBRARY_PATH'} = "$GL/lib";
    }
    if ( ! -f "$GL/setup/globus/setup-simple-ca" )
    {
        print "$GL/setup/globus/setup-simple-ca was not found.\n";
        print "It is required to create a new SimpleCA.\n";
        print "Please double-check that $GL is the correct GLOBUS_LOCATION.\n";
        exit 9;
    }
} 
else 
{
   print "Please set GLOBUS_LOCATION to your install dir.\n";
   exit 1;
}

#GPT_Location needs to be set too
if(!$ENV{'GPT_LOCATION'})
{
    $ENV{'GPT_LOCATION'} = $GL;
}

my $passwdok = 0;
open(PASSFILE, "<$ENV{HOME}/.globus/.simplecapass");
if ( $? eq 0 )
{
   $passwd = <PASSFILE>;
   chomp $passwd;
   if ( length($passwd) >= 4 )
   {
      $passwdok = 1;
      print "Using password from $ENV{HOME}/.globus/.simplecapass\n";
   }
}
close(PASSFILE);

while(!$passwdok)
{
    print "Please enter a password of at least four characters for the CA: ";
    system("stty -echo");
    $passwd = <STDIN>;
    chomp($passwd);
    system("stty echo");

    if (length($passwd) < 4)
    {
        print "\nERROR: Password must be at least four characters\n";
        next;
    }

    print "\nConfirm password:";
    system("stty -echo");
    my $passwd_conf = <STDIN>;
    chomp($passwd_conf);
    system("stty echo");
    print "\n";

    if($passwd ne $passwd_conf)
    {
        print "ERROR: Passwords do not match\n";
    } else
    {
        $passwdok = 1;
    }
}

my $oldumask = umask;
umask 022;
if ( ! -d "$ENV{HOME}/.globus" )
{
   system("mkdir $ENV{HOME}/.globus");
   if ( $? ne 0 )
   {
       print "ERROR:  Unable to create $ENV{HOME}/.globus: $!";
       exit 4;
   }
}

umask 0377;
open(PASSFILE, ">$ENV{HOME}/.globus/.simplecapass");
if ( $? ne 0)
{
   print "ERROR: Unable to open $ENV{HOME}/.globus/.simplecapass for writing\n";
   exit 6;
}
print PASSFILE "$passwd";
close PASSFILE;

umask $oldumask;
       
my $logfile="gt-server-ca.log";
system("touch $logfile");

#
# all the envs should be set up now so we install the CA stuff
#
print "Creating a new simpleCA, logging to $logfile...";
$rc = system("$GL/setup/globus/setup-simple-ca -force -pass $passwd -noint > $logfile 2>&1");
if($rc != 0)
{
    print "setup-simple-ca failed.  See $logfile for details.\n";
    exit 2;
}

print "\nRunning setup-gsi...";
my ($glob) = glob("$GL/setup/globus_simple_ca_*_setup");
$rc = system("$glob/setup-gsi -default -nonroot >> $logfile 2>&1");
if($rc != 0)
{
    print "setup-gsi failed.  See $logfile for details.\n";
    exit 3;
}

$glob =~ s#$GL/setup/globus_simple_ca_(.{8})_setup#$1#;
$simplecahash = $glob;
#$ENV{'GRID_SECURITY_DIR'} = "$GL/etc/";
# system("ln -fs $GL/share/certificates $GL/etc/certificates");
# system("ln -fs $GL/etc/certificates/globus-host-ssl.conf.$simplecahash $GL/etc/globus-host-ssl.conf");
# system("ln -fs $GL/etc/certificates/globus-user-ssl.conf.$simplecahash $GL/etc/globus-user-ssl.conf");
# system("ln -fs $GL/etc/certificates/grid-security.conf.$simplecahash $GL/etc/grid-security.conf");

print "\nYour CA hash is: $simplecahash\n";
print "It is located at ${GL}/share/certificates/${simplecahash}.0\n";
#
#  now request the cert
# 
$hostname = `globus-hostname`;
chomp $hostname;
   
$ENV{X509_CERT_DIR}="$GL/share/certificates";
system("grid-default-ca -ca $simplecahash >> $logfile 2>> $logfile");
$ENV{GRID_SECURITY_DIR}="$GL/etc";

system("grid-cert-request -ca $simplecahash -host $hostname -dir $GL/etc/ -force >> $logfile 2>> $logfile");
if ( $? ne 0 )
{
    print "There was an error requesting a host certificate for $hostname.\n";
    print "Please see $logfile for details.\n";
    exit 10;
}

system("grid-ca-sign -in $GL/etc/hostcert_request.pem -out $GL/etc/hostcert.pem -passin pass:$passwd -force >> $logfile");
if ( $? ne 0 )
{
    print "There was an signing the request for $hostname.\n";
    print "Please see $logfile for details.\n";
    exit 11;
}

# Need -f when copying the key, else it errors out on overwriting a
# file with such strict permissions
system("cp $GL/etc/hostcert.pem $GL/etc/containercert.pem");
system("cp -f $GL/etc/hostkey.pem $GL/etc/containerkey.pem");

print "Your host DN is ";
system("grid-cert-info -subject -file $GL/etc/hostcert.pem");
print "The hostcert is located at ${GL}/etc/hostcert.pem\n";

