#!/usr/bin/perl -w
use CGI qw/:standard/;

use Expect;

my $program = '/home/novotny/myproxy/myproxy-get-delegation'; 
my $username = param(USERNAME);
my $password = param(PASSWORD);
my $lifetime = 30;

# Check length of password
my $len = length ($password);
if (($len < 5) || ($len > 10))
{
  passwordtoolong();
}

# use expect to run the command
#my $command "echo $password |$program";
my $cmd_filehandle = Expect->spawn("$program");

# this looks for the string "myproxy-server:" for 20 seconds
# and failing that, does the "error" subroutine.
unless ($cmd_filehandle->expect(20, "myproxy-server:")) 
{
  error();
}

print $cmd_filehandle "$password\n";

# gather the output into the array
@back = <$cmd_filehandle>;

# close the filehandle to the command
$cmd_filehandle->soft_close();

@back = reverse(@back) ;
$pass = pop(@back);
# now you have an array called @back which has the rest of the output...
print "<pre>\n";
foreach(reverse(@back)) { print; }
print "</pre>\n";


sub accessgranted
{
  print header;
  print "<TITLE>Access Granted</TITLE>";
  print "<FONT FACE=Arial SIZE=3 COLOR=Blue><STRONG>";
  print "A proxy has been retrieved for $username";
  print "</STRONG></FONT>";
}

sub wrongpassword
{
  print header;
  print "<TITLE>Access Denied</TITLE>";
  print "<FONT FACE=Arial SIZE=3 COLOR=Red><STRONG>";
  print "You entered in invalid password to the myproxy-server.";
  print "</STRONG></FONT>";
  exit;
}

sub accessdenied
{
  print header;
  print "<TITLE>Access Denied</TITLE>";
  print "<FONT FACE=Arial SIZE=3 COLOR=Red><STRONG>";
  print "You were denied access to the myproxy-server.";
  print "</STRONG></FONT>";
  exit;
}

sub passwordtoolong
{
  print header;
  print "<TITLE>Incorrect Password</TITLE>";
  print "<FONT FACE=Arial SIZE=3 COLOR=Red><STRONG>";
  print "The password must be between 5 and 10 characters.";
  print "</STRONG></FONT>";
  exit;
}

sub error
{
  print header;
  print  "<TITLE>Error!</TITLE>";
  print "<FONT FACE=Arial SIZE=3 COLOR=Red><STRONG>";
  print "Unable to run $program!";
  print "</STRONG></FONT>";
  exit;
}

