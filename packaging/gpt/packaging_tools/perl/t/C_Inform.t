use strict;
use Data::Dumper;
use File::Find;
use Cwd;
# Initialise filenames and check they're there

print "1..11\n";

my $t = 1;

##############################################################################
#                   S U P P O R T   R O U T I N E S
##############################################################################

##############################################################################
# Print out 'n ok' or 'n not ok' as expected by test harness.
# First arg is test number (n).  If only one following arg, it is interpreted
# as true/false value.  If two args, equality = true.
#

sub ok {
  my($n, $x, $y) = @_;
  die "Sequence error got $n expected $t" if($n != $t);
  $x = 0 if(@_ > 2  and  $x ne $y);
  print(($x ? '' : 'not '), 'ok ', $t++, "\n");
}

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
  $gpath = $ENV{GLOBUS_LOCATION};

}

if (!defined($gpath))
{
   die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
}


@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::PkgMngmt::Inform;

local *FAKELOG;

my $result;

my $nolog = new Grid::GPT::PkgMngmt::Inform();
my $stdlog = new Grid::GPT::PkgMngmt::Inform(verbose => 1);

$result = `rm t/mylog.rslt` if -f "t/mylog.rslt";

my $mylog = new Grid::GPT::PkgMngmt::Inform(log => "t/mylog.rslt");

#inform nolog
open(FAKELOG, ">t/nolog1.rslt");
$nolog->inform("working hard",0,*FAKELOG);
close FAKELOG;
$result = ! system("diff -b -w t/nolog1.rslt t/nolog1.exp");
ok($t, $result);
#inform override nolog
open(FAKELOG, ">t/nolog2.rslt");
$nolog->inform("working hard",1,*FAKELOG);
close FAKELOG;
$result = ! system("diff -b -w t/nolog2.rslt t/nolog2.exp");
ok($t, $result);

#inform stdlog
open(FAKELOG, ">t/stdlog1.rslt");
$stdlog->inform("working hard",0,*FAKELOG);
close FAKELOG;
$result = ! system("diff -b -w t/stdlog1.rslt t/stdlog1.exp");
ok($t, $result);

#inform mylog
open(FAKELOG, ">t/mylog1.rslt");
$mylog->inform("working hard",0,*FAKELOG);
close FAKELOG;
$result = ! system("diff -b -w t/mylog1.rslt t/mylog1.exp");
ok($t, $result);

my $result;

#good action nolog
$result = $nolog->action("t/indirect.sh");
ok($t, $result == 0);

#good action stdlog
$result = $stdlog->action("t/indirect.sh");
ok($t, $result == 0);

#good action mylog
$result = $mylog->action("t/indirect.sh");
ok($t, $result == 0);

#bad action nolog
$result = $nolog->action("t/indirect.sh error");
ok($t, $result > 0);

#bad action stdlog
$result = $stdlog->action("t/indirect.sh error");
ok($t, $result > 0);

#bad action mylog
$result = $mylog->action("t/indirect.sh error");
ok($t, $result > 0);

$result = ! system("diff -b -w t/mylog.rslt t/mylog.exp");
ok($t, $result);
