
# this script expects repository as an arg
# and cvs log info on stdin

use strict;

my $CVSROOT             = $ENV{'CVSROOT'};
my $PMT_DIR             = "$CVSROOT/pmt_active";
my $PMT_PACKAGE_DEF     = "$PMT_DIR/package.def";
my $PMT_BRANCH_DEF      = "$PMT_DIR/branch.def";
my $PMT_TEMPLATE_DIR    = "$PMT_DIR/templates";

# verify location of package and branch databases
(-d $PMT_DIR)           || die("PMT Error: Can't find PMT dir at $PMT_DIR!");
(-f $PMT_PACKAGE_DEF)   || die("PMT Error: Missing package defs at $PMT_PACKAGE_DEF!");
(-f $PMT_BRANCH_DEF)    || die("PMT Error: Missing branch defs at $PMT_BRANCH_DEF!");
(-d $PMT_TEMPLATE_DIR)  || die("PMT Error: Can't find template dir at $PMT_TEMPLATE_DIR!");

# using RESPOSITORY and package db, find this package's root dir and template file
# if none can be found, we dont do anything for this package

open(PACKAGE_DEF, $PMT_PACKAGE_DEF)
    || die("PMT Error: could not open $PMT_PACKAGE_DEF");

my $repository          = shift(@ARGV) || die("PMT Error: Missing argument!");
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
            print("PMT Warning: Ignoring bad line in $PMT_PACKAGE_DEF\n$_\n");
        }
    }
}

close(PACKAGE_DEF);

if(!$package_loc)
{
    exit(0);
}

my $template_file = "$PMT_TEMPLATE_DIR/$template_filename";
(-f $template_file)
    || die("PMT Error: Missing template file at $template_file\n");

# see if the RCS file exists. if not, its never been requested for
# any branches yet, so we dont need to do anything
# need to check Attic also
my $rcsfile = "$package_loc/$template_filename,v";
if(!-f $rcsfile) 
{
    $rcsfile = "$package_loc/Attic/$template_filename,v";
    (-f $rcsfile) 
        || print("PMT Warning: Package defined for PMT but no users\n") && exit(0);
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

# now check to see what tags are actually defined AND NOT dead in
# rcsfile.  Those that are dead or not defined dont get updates
# if we end up removing all set tags, then we're done.
# this is made more difficult because we use tags that rcs doesnt like
# (those that contain '-') so we need to match symbols to a branch rev
# and query on the numeric revision
my %tag_version;

$_ = `rlog -h $rcsfile 2>&1`;
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
            if(s/.*selected revisions: (\d+).*/$1/s)
            {
                if($_ == 0)
                {
                    # no active revision for this tag
                    delete($tags{$tag});
                }
            }
            elsif(!m/no side branches present/)
            {
                # if output specifies 'no side branches present'
                # we keep it, this will just be the first update on that
                # branch
                
                # any other output is erroneous
                die("PMT Error: couldn't parse rlog output");
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
    die("PMT Error: couldn't parse rlog output");
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
    open(BRANCH_DEF, $PMT_BRANCH_DEF)
        || die("PMT Error: could not open $PMT_BRANCH_DEF");

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
                print("PMT Warning: Ignoring bad line in $PMT_BRANCH_DEF\n$_\n");
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
                print("PMT Warning: Can't find branch id for $key...\n");
                print("PMT Warning: Using 0\n");
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
            die("PMT Error: could not create lock: $!");
        }
        else
        {
            print("PMT Waiting 15 seconds to aquire lock...\n");
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
    system("co -q -l$tag_version{$tag} $parsed_file $rcsfile");

    system("cat $template_file | "
        . "sed -e 's/\@PMT_TIMESTAMP\@/$timestamp/' "
        . "-e 's/\@PMT_BRANCH_ID\@/$tag_id/' > $parsed_file");
    
    system("ci -r$tag_version{$tag} -d'$timestring' -m. $parsed_file $rcsfile");
}

print("PMT: $template_filename has been updated.\n");
print("PMT: You should do a cvs update in this package's root directory\n");

# unlock version file
if($remove_lock)
{
    if(!rmdir($lockfile))
    {
        die("PMT Error: unable to remove lock: $!");
    }
}

exit(0);
