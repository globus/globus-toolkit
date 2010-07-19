#!/usr/bin/perl
#
#   name: createlist.pl
# author: Chase Phillips, <cphillip@ncsa.uiuc.edu>
#
# recursively get file info and format the data into the epm filelist 'standard'.
#
# gpt.list =
#   # type mode owner group destination source
#   f 644 root sys /usr/bin/xyzzy xyzzy
#   c 644 root sys /etc/foo.conf foo.conf
#   d 755 root sys /var/spool/foo -
#   f 644 root sys /etc/bar.conf foobar/baz.bar
#

use Getopt::Long;
use Cwd;
use Cwd 'abs_path';
use Data::Dumper;

# my $prepend = "/usr/local/gpt";

sub createFileList
{
    my ($dir, $prepend, $exclude) = @_;
    my ( $main, $str ) = ( [], undef );
    my $old_dir;

    if ( defined($prepend) )
    {
        if ( length($prepend) == 0 )
        {
            $prepend = undef;
        }
        else
        {
            $prepend .= "/";
            $prepend =~ s|/+|/|g;
        }
    }

    $exclude = format_exclude($dir, $exclude);

    #
    # get a listing of all filesystem entries relative to our main directory
    #

    $old_dir = cwd();
    chdir($dir);
    main_harvest($main, ".", $exclude);
    chdir($old_dir);

#    printf("%s", Dumper($main));

    #
    # now that we have our big honkin' list, we can specialize the data
    # to fit epm's filelist format
    #

    $str = format_harvest($main, $prepend);

    return $str;
}

### format_exclude( $dir, $exclude )
#
# take an array of paths and translate them into an anonymous hash (keys=inode)
#

sub format_exclude
{
    my ($dir, $exclude) = @_;
    my ($tmp, $newexclude, $inode);

    $dir = abs_path($dir);

    for my $e (@$exclude)
    {
        #
        # if the entry in @exclude isn't an absolute path, prepend the directory
        # for which we're gonna grab a filelist
        #

        if ($e !~ /^\//)
        {
            $e = $dir . "/" . $e;
        }

        $inode = getInode($e);
        $newexclude->{$inode} = 1;
    }

    return $newexclude;
}

sub main_harvest
{
    my ($main, $dir, $exclude) = @_;

    $dir =~ s|/+$||g;

    #
    # turn off output buffering
    #

    $| = 1;

    harvest_fs($main, $dir, $exclude);

    #
    # turn on output buffering
    #

    $| = 0;
}

sub format_harvest
{
    my ($dirlist, $prepend) = @_;
    my (@fslist, $str);

    $str = "";

    #
    # loop over our 'dirlist' element, and append $fsstr from each entry
    # onto $str
    #

    for my $e (@$dirlist)
    {
        $fsstr = format_harvest_entry($e, $prepend);

         if (length($str) gt 0)
         {
             $fsstr = "\n" . $fsstr;
         }

         $str .= $fsstr;
    }

    return $str;
}

sub format_harvest_entry
{
    my ($fshash, $prepend) = @_;
    my ($value);

    $name = $fshash->{'name'};
    $type = $fshash->{'type'};
    $path = $fshash->{'path'};
    $spec = $fshash->{'spec'};

    if ($type eq "d")
    {
        $fsstr = get_dir_info($spec, $prepend);
    }
    elsif ($type eq "f")
    {
        $fsstr = get_file_info($spec, $prepend);
    }
    elsif ($type eq "l")
    {
        $fsstr = get_link_info($spec, $prepend);
    }

    return $fsstr;
}

sub harvest_fs()
{
    my ($dirlist, $current_dir, $exclude) = @_;
    my (@entries);
    my ($name, $type, $path);

    @entries = get_entries($current_dir, $exclude);
    push(@$dirlist, @entries);

    if (scalar(@entries) gt 0)
    {
        for my $e (@entries)
        {
            #
            # pull out critical data
            #

            $name = $e->{'name'};
            $type = $e->{'type'};
            $path = $e->{'path'};
            $spec = $e->{'spec'};

            if ($type eq "d")
            {
                # call ourselves again
                harvest_fs($dirlist, "$current_dir/$name", $exclude);
            }
        }
    }
}

### getInode( $filename )
#
# take a filename and then return its inode.  (this function is symbolic-link-safe)
#

sub getInode
{
    my ($filename) = @_;
    my ($inode, $data);

    if ( -l $filename )
    {
        $inode = (lstat($filename))[1];
    }
    else
    {
        $inode = (stat($filename))[1];
    }

    return $inode;
}

sub get_entries
{
    my ($dirname, $exclude) = @_;
    my (@entries, @newentries);
    my ($node, $inode);

    opendir(MYDIR, $dirname);
    @entries = readdir(MYDIR);
    closedir(MYDIR);

    for my $f (@entries)
    {
        $node = {};

        if ( ($f eq ".") || ($f eq "..") )
        {
            #
            # we don't care about these special directories
            #

            next;
        }

        $inode = getInode("$dirname/$f");
        if ( $exclude->{$inode} )
        {
            #
            # this file already exists in our defined list of excluded files.  don't grab it.
            #

            next;
        }

        $node->{'name'} = $f;
        $node->{'path'} = "$dirname/$f";
        $node->{'path'} =~ s|^./||;
        $node->{'spec'} = {};

        if ( -d "$dirname/$f" )
        {
            $node->{'type'} = "d";
            $node->{'spec'} = set_dir_info($node->{'path'});
        }
        elsif ( -l "$dirname/$f" )
        {
            $node->{'type'} = "l";
            $node->{'spec'} = set_link_info($node->{'path'});
        }
        elsif ( -f "$dirname/$f" )
        {
            $node->{'type'} = "f";
            $node->{'spec'} = set_file_info($node->{'path'});
        }
        else
        {
            $node->{'type'} = "?";
        }

        push(@newentries, $node);
    }

    return @newentries;
}

### get_link_info( $spec, $prepend )
#
# get symbolic link info
#

sub get_link_info
{
    my ($spec, $prepend) = @_;
    my ($str);

    # l mode user group destination source
    # eg: l 000 root sys /usr/bin/foobar foo

    $mode = $spec->{'mode'};
    $value = $spec->{'value'};
    $uname = $spec->{'uname'};
    $gname = $spec->{'gname'};
    $filename = $spec->{'filename'};

    if ($filename !~ /^\//)
    {
        $destfilename = $prepend . $filename;
    }
    else
    {
        $destfilename = $filename;
    }

    $str = "l 000 $uname $gname $destfilename $value";

    return $str;
}

sub set_link_info
{
    my ($filename) = @_;
    my (@info);
    my ($oldmode, $mode);
    my ($uid, $gid, $uname, $gname);
    my ($value);

    my $node = {};

    # l mode user group destination source
    # eg: l 000 root sys /usr/bin/foobar foo

    @info = (lstat($filename));

    #
    # i know nothing about the mode field (containing type and permissions).  here i
    # just mask off the relevant portion of the mode and grab the permissions.
    #

    $oldmode = @info[2];
    $mode = sprintf("%04o", $oldmode & 07777);
    $node->{'mode'} = $mode;

    #
    # get uid and gid
    #

    $uid = @info[4];
    $uname = getpwuid($uid);
    $node->{'uname'} = $uname;

    $gid = @info[5];
    $gname = getgrgid($gid);
    $node->{'gname'} = $gname;

    #
    # get the name of the file to which the link points
    #

    die "Can't readlink $filename: $!" unless defined($value = readlink($filename));
    $node->{'value'} = $value;
    $node->{'filename'} = $filename;

    return $node;
}

### get_file_info( $spec, $prepend )
#
# get regular file info
#

sub get_file_info
{
    my ($spec, $prepend) = @_;
    my ($str);

    # f mode user group destination source
    # eg: f 755 root sys /usr/bin/foo foo

    $mode = $spec->{'mode'};
    $uname = $spec->{'uname'};
    $gname = $spec->{'gname'};
    $filename = $spec->{'filename'};

    if ($filename !~ /^\//)
    {
        $destfilename = $prepend . $filename;
    }
    else
    {
        $destfilename = $filename;
    }

    $str = "f $mode $uname $gname $destfilename $filename";

    return $str;
}

sub set_file_info
{
    my ($filename) = @_;
    my (@info);
    my ($oldmode, $mode);
    my ($uid, $gid, $uname, $gname);
    my ($value);

    my $node = {};

    # f mode user group destination source
    # eg: f 755 root sys /usr/bin/foo foo

    @info = (stat($filename));

    #
    # i know nothing about the mode field (containing type and permissions).  here i
    # just mask off the relevant portion of the mode and grab the permissions.
    #

    $oldmode = @info[2];
    $mode = sprintf("%04o", $oldmode & 07777);
    $node->{'mode'} = $mode;

    #
    # get uid and gid
    #

    $uid = @info[4];
    $uname = getpwuid($uid);
    $node->{'uname'} = $uname;

    $gid = @info[5];
    $gname = getgrgid($gid);
    $node->{'gname'} = $gname;

    $node->{'filename'} = $filename;

    return $node;
}

### get_dir_info( $spec, $prepend )
#
# get dir-specific info
#

sub get_dir_info
{
    my ($spec, $prepend) = @_;
    my ($str);

    # d mode user group destination source
    # eg: d 755 root sys /usr/bin/foo -

    $mode = $spec->{'mode'};
    $uname = $spec->{'uname'};
    $gname = $spec->{'gname'};
    $dirname = $spec->{'dirname'};

    if ($dirname !~ /^\//)
    {
        $dirname = $prepend . $dirname;
    }
    else
    {
        $dirname = $dirname;
    }

    $str = "d $mode $uname $gname $dirname -";

    return $str;
}

sub set_dir_info
{
    my ($dirname) = @_;
    my (@info);
    my ($oldmode, $mode);
    my ($uid, $gid, $uname, $gname);
    my ($value);

    my $node = {};

    # d mode user group destination source
    # eg: d 755 root sys /usr/bin/foo -

    @info = (stat($dirname));

    #
    # i know nothing about the mode field (containing type and permissions).  here i
    # just mask off the relevant portion of the mode and grab the permissions.
    #

    $oldmode = @info[2];
    $mode = sprintf("%04o", $oldmode & 07777);
    $node->{'mode'} = $mode;

    #
    # get uid and gid
    #

    $uid = @info[4];
    $uname = getpwuid($uid);
    $node->{'uname'} = $uname;

    $gid = @info[5];
    $gname = getgrgid($gid);
    $node->{'gname'} = $gname;

    $node->{'dirname'} = $dirname;

    return $node;
}

1;

__END__
