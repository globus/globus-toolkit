#!/usr/bin/perl

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 


# this script expects source file as an arg

# types are defined with
# GlobusVarArgDefine(name, rettype, function, ... /* fixed params */)
#  the enum will be the first param after the fixed params followed by
# any params defined in the GlobusVarArgEnum block

# enums can be preceded with 2 comment blocks, the first starting with
# GlobusVarArgEnum(<comma separated list of types>) The second is the vararg
# parameter list

use strict;

# these two are used as 'static' variables for following function
my $line = '';
my $comment = '';
# function returns either whole comment or everything between comments
sub get_next_blob()
{
    my $blob = '';
    
    if(!$line && !defined($line = <SOURCE>))
    {
        return '';
    }
    
    while($line)
    {
        if($comment)
        {
            # still looking for the end of the comment
            if($line =~ m/\*\//)
            {
                my $comment_end = $line;
                
                # extract the comment portion
                $comment_end =~ s/(.*?\*\/).*\n?/$1/;
                $comment_end = $comment . $comment_end;
                $comment = '';
                
                # keep remainder of line
                $line =~ s/.*?\*\/(.*)/$1/;
                
                return $comment_end;
            }
            
            $comment .= $line;
        }
        elsif($line =~ m/\/\*/)
        {
            # got a beginning of a comment
            my $prefix = $line;
            
            # keep the comment portion
            $line =~ s/.*?\/\*(.*)/$1/;
    
            # save the preceding portion
            $prefix =~ s/(.*?)\/\*.*\n?/$1/;
            $blob .= $prefix;
            
            # make sure this isn't a /* embedded in a string
            # this does not catch multi-line strings (which are deprecated in C)
            # this is hacky perl which counts the number of matches in a string
            my $count = () = $prefix =~ m/(?<!\\)\"/g;
            $count -= () = $prefix =~ m/'\"'/g;
            if($count % 2)
            {
                # odd number of un-escaped double quotes... this /* is embedded
                $blob .= '/*';

                # get the rest of the string so we even up quote count again
                $prefix = $line;
                $prefix =~ s/(.*?(?<!\\)\").*\n?/$1/;
                
                $line =~ s/.*?(?<!\\)\"(.*)/$1/;
                
                $blob .= $prefix;
            }
            else
            {
                $comment = '/*';
                if($blob)
                {
                    return $blob;
                }
            }
            
            redo;
        }
        else
        {
            # not a comment
            $blob .= $line;
        }
        
        $line = <SOURCE>;
    }
    
    # only get here on eof
    if(!$blob)
    {
        $blob = $comment;
    }
    return $blob;
}

sub strip_comments($)
{
    my $str = shift;
    return join("", split(/(?:^\s*(?:\/\*+|\*+(?!\/)))|(?:\*+\/)/m, $str));
}

sub normalize_params($)
{
    my $str = shift;
    $str =~ s/^\s*(.*?)\s*$/$1/s;   # trim whitespace from ends
    $str =~ s/\s+/ /sg;             # collaspe all whitespace into single space
    $str =~ s/\s*,\s*/, /sg;        # make all ',' have only one space on right
    return $str;
}

############################################################################

my $source_file          = shift(@ARGV) || die("Error: Missing argument!");
my %types;
my $functions = '';

open(SOURCE, $source_file)
    || die("Error: could not open $source_file");

while((my $blob = get_next_blob()))
{
    if($blob =~ m/^\/\*/)
    {
        my $stripped = strip_comments($blob);
        my @matches = ($stripped =~ m/GlobusVarArgDefine\(\s*(.*?)\s*\)/sg);
        
        if(@matches)
        {
            # strip from blob
            $blob =~ s/GlobusVarArgDefine\(.*?\)//sg;
            foreach my $match (@matches)
            {
                my @params = split(/\s*,\s*/s, $match);
                if(@params >= 3)
                {
                    my $type = shift(@params);
                    my $rettype = shift(@params);
                    my $func_name = shift(@params);
                    
                    $types{$type} = {
                        'rettype' => $rettype,
                        'name' => $func_name,
                        'begin_prototype' => 
                            '(' . normalize_params(join(',', @params)) };
                }
                else
                {
                    print(STDERR
                        "Warning: GlobusVarArgDefine has too few args\n");
                }
            }
        }
        elsif($stripped =~ s/^.*GlobusVarArgEnum\((.*?)\).*$/$1/s)
        {
            # stripped types that we need to output for
            my @types = split(/\s*,\s*/s, $stripped);
            my $docblock;
            my $end_prototype = ')';
            
            # strip GlobusVarArgEnum from blob
            $blob =~ s/GlobusVarArgEnum\(.*?\)/\@overload/s;
            $docblock = $blob . "\n";
            
            # next blob is either an optional prototype comment or the enum
            $blob = get_next_blob();
            # we might get all whitespace first
            if($blob =~ m/^\s+$/s)
            {
                $blob = get_next_blob();
            }
            
            if($blob =~ m/^\/\*/)
            {
                # we've got the var arg parameters now
                $blob = strip_comments($blob);
                if(!($blob =~ m/^\s*$/s))
                {
                    $end_prototype = 
                        ', ' . normalize_params($blob) . $end_prototype;
                }
                
                $blob = get_next_blob();
            }
            
            while($blob =~ m/^((\/\*)|(\s*$))/)
            {
                # any additional comments or whitespace we just spew out
                print($blob);
                $blob = get_next_blob();
            }
            
            # blob now has to be enum or bust
            my $enum = $blob;
            if($enum =~ s/^\s*(\w+).*$/$1/s)
            {
                my $comment = ' /** See usage for: ';
                my $found = 0;
                
                # create function sigs
                foreach my $type (@types)
                {
                    if(defined($types{$type}))
                    {
                        my $function = $types{$type}{'name'} .
                            $types{$type}{'begin_prototype'} . ', ' .
                            $enum . $end_prototype;
                        
                        $functions .= $docblock . 
                            $types{$type}{'rettype'} . " $function;\n";
                        
                        if($found)
                        {
                            $comment .= ', ';
                        }
                       
                        $comment .= "\@link $function " . 
                            $types{$type}{'name'} . ' @endlink';
                        $found = 1;
                    }
                    else
                    {
                        print(STDERR
                      "Warning: undefined type '$type' in GlobusVarArgEnum\n");
                    }
                }
                
                $comment .= " */\n";
                if($found)
                {
                    $blob = $comment . $blob;
                    if(0)
                    {
                    # add comment with references to usage
                    if($blob =~ m/[^,}]*,/)
                    {
                        $blob =~ s/^(\s*\w+\s*(=[^,]+)?,)/$1$comment/s;
                    }
                    else
                    {
                        # last enum in the block
                        $blob =~ 
                           s/^(\s*\w+(\s*=[^}]+?(?=\n\s*(}|$)))?)/$1$comment/s;
                    }
                }
                }
                else
                {
                    print($docblock);
                }
            }
            else
            {
                # not enum, warn and spew docblock
                print(STDERR
                 "Warning: missing enum value after GlobusVarArgEnum block\n");
                print($docblock);
            }
        }
    }

    print($blob);
}

print($functions);

exit(0);
