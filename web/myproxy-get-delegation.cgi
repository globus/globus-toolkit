#!/usr/bin/perl -w
# Thanks to Steve Mock @SDSC for expect stuff
#
use CGI qw/:standard/;

use Expect;

# Edit this line to reflect location of myproxy-get-delegation
my $program  = "/home/novotny/myproxy/myproxy/myproxy/myproxy-get-delegation"; 

my $username    = param(USERNAME);
my $password    = param(PASSWORD);
my $portal_life = param(PORTALLIFE);

my $outfile = "$username.cred";
my $args     = "-s localhost -l $username -t $portal_life -o $outfile";
my $lifetime = 30;

# Check length of password
my $len = length ($password);
if (($len < 5) || ($len > 10))
{
  passwordtoolong();
}

# use expect to run the command
my $cmd_filehandle = Expect->spawn("$program $args");

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
  print "Unable to run myproxy-get-delegation!";
  print "</STRONG></FONT>";
  exit;
}

