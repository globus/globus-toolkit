#!/usr/local/bin/perl

use strict;

my $CVSROOT             = $ENV{'CVSROOT'};
my $PMT_DIR             = "$CVSROOT/pmt_active";
my $PMT_BRANCH_DEF      = "$PMT_DIR/branch.def";

(-d $PMT_DIR)           || die("PMT Error: Can't find PMT dir at $PMT_DIR!");
(-f $PMT_BRANCH_DEF)    || die("PMT Error: Missing branch defs at $PMT_BRANCH_DEF!");

my $branch_id = shift();
my $branch_name;

defined($branch_id) || die("Missing argument!\n");

open(BRANCH_DEF, $PMT_BRANCH_DEF)
        || die("PMT Error: could not open $PMT_BRANCH_DEF");

while(defined($_ = <BRANCH_DEF>))
{
    if(!m/^#/)
    {   
        my @fields = split();
        if(@fields == 2)
        {
            if($fields[1] == $branch_id)
            {
                $branch_name = $fields[0];
                last;
            }
        }
        elsif(@fields)
        {
            print("PMT Warning: Ignoring bad line in $PMT_BRANCH_DEF\n$_\n");
        }
    }
}
    
close(BRANCH_DEF);

if($branch_name)
{
    print("$branch_name\n");
}
else
{
    print("Branch id $branch_id does not exist in $PMT_BRANCH_DEF\n");
}

exit(0);

