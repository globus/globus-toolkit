
# this script expects repository as an arg
# and cvs log info on stdin

use strict;

my $CVSROOT             = $ENV{'CVSROOT'};
my $DIRT_DIR            = "$CVSROOT/dirt_active";
my $DIRT_PACKAGE_DEF    = "$DIRT_DIR/package.def";
my $DIRT_BRANCH_DEF     = "$DIRT_DIR/branch.def";
my $DIRT_TEMPLATE_DIR   = "$DIRT_DIR/templates";

# verify location of package and branch databases
(-d $DIRT_DIR)           || die("DiRT Error: Can't find DiRT dir at $DIRT_DIR!");
(-f $DIRT_PACKAGE_DEF)   || die("DiRT Error: Missing package defs at $DIRT_PACKAGE_DEF!");
(-f $DIRT_BRANCH_DEF)    || die("DiRT Error: Missing branch defs at $DIRT_BRANCH_DEF!");
(-d $DIRT_TEMPLATE_DIR)  || die("DiRT Error: Can't find template dir at $DIRT_TEMPLATE_DIR!");

# using RESPOSITORY and package db, find this package's root dir and template file
# if none can be found, we dont do anything for this package

open(PACKAGE_DEF, $DIRT_PACKAGE_DEF)
    || die("DiRT Error: could not open $DIRT_PACKAGE_DEF");

my $repository          = shift(@ARGV) || die("DiRT Error: Missing argument!");
my $package_loc;
my $template_filename;

while(!$package_loc && defined($_ = <PACKAGE_DEF>))
{
    # ignore comment lines
    if(!m/^#/)
    {   
        my @fields = split();
        if(@fields == 3)
        {
            if($repository =~ m/^$fields[1]/)
            {
                $package_loc = "$CVSROOT/$fields[1]";
                $template_filename = $fields[2];
            }
        }
        elsif(@fields)
        {
            print("DiRT Warning: Ignoring bad line in $DIRT_PACKAGE_DEF\n$_\n");
        }
    }
}

close(PACKAGE_DEF);

if(!$package_loc)
{
    exit(0);
}

my $template_file = "$DIRT_TEMPLATE_DIR/$template_filename";
(-f $template_file)
    || die("DiRT Error: Missing template file at $template_file\n");

# see if the RCS file exists. if not, its never been requested for
# any branches yet, so we dont need to do anything
# need to check Attic also
my $rcsfile = "$package_loc/$template_filename,v";
if(!-f $rcsfile) 
{
    $rcsfile = "$package_loc/Attic/$template_filename,v";
    (-f $rcsfile) 
        || print("DiRT Warning: Package defined for DiRT but no users\n") && exit(0);
}

# parse log message for the tags we need to update
# note: this rather complex parse is mostly to handle strange
# commits involving mutliple tags that is likely never to occur
# The worst case log might look something like:
# 
# Update of <absolute path to repository>
# In directory <machine>:<working dir path>
# 
# Modified Files:
#         globus_ftp_client.c 
#       Tag: globus-beta-branch-sub-versions
#         globus_ftp_client_state.c 
#       Tag: globus-beta-branch
#         globus_ftp_client_throughput_plugin.h 
# Added Files:
#       Tag: globus-beta-branch
#         new-a new-b new-c 
# Removed Files:
#       Tag: globus-beta-branch-sub-versions
#         globus_ftp_client.h 
#       Tag: globus-beta-branch
#         globus_ftp_client_attr.c 
#       No tag
#         globus_ftp_client_data.c 
# Log Message:
# hi

my %tags;
my $can_be_trunk = 0;
while(defined($_ = <STDIN>) && !m/^Log Message:$/)
{
    chomp();
    
    # see if its a '(Modified|Added|Removed) Files:' line
    if(m/^(Modified|Added|Removed) Files:$/)
    {
        $can_be_trunk = 1;
    }
    else
    {
        # check for tag line, otherwise this might be on the trunk
        if(s/^\s+Tag: (.*)$/$1/)
        {
            $tags{$_} = 0;
        }
        elsif($can_be_trunk || m/^\s+No tag$/)
        {
            $tags{'TRUNK'} = 1;
        }
        $can_be_trunk = 0;
    }
}

# consume rest of input
while(defined(<STDIN>)) {}

# now check to see what tags are actually defined AND NOT dead in
# rcsfile.  Those that are dead or not defined dont get updates
# if we end up removing all set tags, then we're done.
# this is made more difficult because we use tags that rcs doesnt like
# (those that contain '-') so we need to match symbols to a branch rev
# and query on the numeric revision
my %tag_version;
my $save_rlog;

$_ = `rlog -h $rcsfile 2>&1`;
$save_rlog = $_;
if(s/.*symbolic names:\s*(.*)keyword substitution:.*/$1/s)
{
    %tag_version = split(/[ \t\n:]+/);
    # the TRUNK doesn't end up as a symbolic name. 
    # so add it here; it has empty version
    $tag_version{'TRUNK'} = '';
    
    my @tags = keys(%tags);
    
    foreach my $tag (@tags)
    {
        if(defined($tag_version{$tag}))
        {
            if($tag ne 'TRUNK') 
            {
                # cvs uses 'magic revisions' for branches, need to fix
                $tag_version{$tag} =~ s/^(.*)\.0\.(\d+)$/$1.$2/;
            }
            
            # this tag is defined, so now we need to be sure its active
            $_ = `rlog -r$tag_version{$tag}. -sExp $rcsfile 2>&1`;
            $save_rlog = $_;
            if(s/.*selected revisions: (\d+).*/$1/s)
            {
                if($_ == 0)
                {
                    # no active revision for this tag
                    delete($tags{$tag});
                }
            }
            elsif(!m/no side branches present/ && 
                !m/revision $tag_version{$tag} absent/)
            {
                # if output specifies 'no side branches present' or 
                # 'revision 1.4.4 absent' we keep it, this will just be the
                # first update on that branch
                
                # any other output is erroneous
                die("DiRT Error: couldn't parse rlog output\n$save_rlog");
            }
        }
        else
        {
            # this tag is not even defined, don't do it
            delete($tags{$tag});
        }
    }
}
else
{
    die("DiRT Error: couldn't parse rlog output\n$save_rlog");
}

my $count = scalar(keys(%tags));
if($count == 0)
{
     exit(0);
}

# for all tags we need to update, lookup numeric id in branch db and 
# if branch id doesnt exist, use 0
# (1 is always used for trunk, dont need to lookup)
if(!($count == 1 && $tags{'TRUNK'}))
{
    open(BRANCH_DEF, $DIRT_BRANCH_DEF)
        || die("DiRT Error: could not open $DIRT_BRANCH_DEF");

    while($count && defined($_ = <BRANCH_DEF>))
    {
        if(!m/^#/)
        {   
            my @fields = split();
            if(@fields == 2)
            {
                if(defined($tags{$fields[0]}))
                {
                    $tags{$fields[0]} = $fields[1];
                    $count--;
                }
            }
            elsif(@fields)
            {
                print("DiRT Warning: Ignoring bad line in $DIRT_BRANCH_DEF\n$_\n");
            }
        }
    }
    
    close(BRANCH_DEF);
    
    # warn users if there are any unknown branch ids
    if($count)
    {
        while((my $key, my $val) = each(%tags))
        {
            if($val == 0)
            {
                print("DiRT Warning: Can't find branch id for $key...\n");
                print("DiRT Warning: Using 0\n");
            }
        }
    }
}

# lock this package's version file
# cvs may have already locked this for me... I'll assume that if I own
# the lock, it is for this instance of cvs 
my $remove_lock = 0;
my $lockfile = "$package_loc/#cvs.lock";

if(!(-d $lockfile  && -o $lockfile))
{
    $remove_lock = 1;
    while(!mkdir($lockfile, 0770))
    {
        if(!-d $lockfile)
        {
            die("DiRT Error: could not create lock: $!");
        }
        else
        {
            print("DiRT Waiting 15 seconds to acquire lock...\n");
            sleep 15;
        }
    }
}

# for each tag,
# create a new copy of the template with timestamp and branch id
# and check this new copy in with appropriate tag arguments
my $parsed_file = "$package_loc/$template_filename";
my $timestamp = time();
my $timestring = gmtime($timestamp);

while((my $tag, my $tag_id) = each(%tags))
{
    system("rm -f $parsed_file");
    system("co -q -l$tag_version{$tag} $parsed_file $rcsfile 2> /dev/null");

    system("cat $template_file | "
        . "sed -e 's/\@DIRT_TIMESTAMP\@/$timestamp/' "
        . "-e 's/\@DIRT_BRANCH_ID\@/$tag_id/' > $parsed_file");
    
    system("ci -r$tag_version{$tag} -d'$timestring' -m. $parsed_file $rcsfile");
}

print("DiRT: $template_filename has been updated.\n");
print("DiRT: You should do a cvs update in this package's root directory\n");

# unlock version file
if($remove_lock)
{
    if(!rmdir($lockfile))
    {
        die("DiRT Error: unable to remove lock: $!");
    }
}

exit(0);

