#!/usr/local/bin/perl

use strict;

my $CVSROOT             = $ENV{'CVSROOT'};
my $DIRT_DIR            = "$CVSROOT/dirt_active";
my $DIRT_BRANCH_DEF     = "$DIRT_DIR/branch.def";

(-d $DIRT_DIR)           || die("DIRT Error: Can't find DIRT dir at $DIRT_DIR!");
(-f $DIRT_BRANCH_DEF)    || die("DIRT Error: Missing branch defs at $DIRT_BRANCH_DEF!");

my $branch_id = shift();
my $branch_name;

defined($branch_id) || die("Missing argument!\n");

open(BRANCH_DEF, $DIRT_BRANCH_DEF)
        || die("DIRT Error: could not open $DIRT_BRANCH_DEF");

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
            print("DIRT Warning: Ignoring bad line in $DIRT_BRANCH_DEF\n$_\n");
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
    print("Branch id $branch_id does not exist in $DIRT_BRANCH_DEF\n");
}

exit(0);
