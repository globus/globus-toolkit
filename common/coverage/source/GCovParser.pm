# Copyright 1999-2008 University of Chicago
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

package Globus::Coverage::GCovParser;

use strict;
use Cwd;
use File::Find;
use Globus::Coverage::Package;
use Globus::Coverage::Parser;

@Globus::Coverage::GCovParser::ISA = qw(Globus::Coverage::Parser);

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);
    
    bless $self, $class;

    return $self;
}

sub process
{
    my $self = shift;
    my $packageinfo;
    
    $packageinfo = $self->{PACKAGE} =
        new Globus::Coverage::Package($self->package_name());

    $self->run_gcov();

    return $self->{PACKAGE};
}

# Find all basic block files in the package directory, then
# - run gcov. All summary info to stdout is parsed into branch/statement counts,
#   then the generated .gcov file with annotated source is parsed into the
#   corresponding Globus::Coverage::File object
sub run_gcov {
    my $self = shift;
    my $filename = shift;
    my $package_info = $self->{PACKAGE};

    File::Find::find({wanted => sub { $self->find_basic_block} },
                    $self->{PACKAGE_DIR});
}

sub find_basic_block
{
    my $self = shift;
    my $package_info = $self->{PACKAGE};

    if (/^\.libs\z/s && ($File::Find::prune = 1))
    {
        return;
    }
    if (/^.*\.bb\z/s) {
        $self->find_basic_block3(@_);
    }
    elsif (/^.*\.gcno\z/s) {
        $self->find_basic_block4(@_);
    }
}

sub find_basic_block3
{
    my $self = shift;
    my $package_info = $self->{PACKAGE};

    if (/^\.libs\z/s && ($File::Find::prune = 1))
    {
        return;
    }
    if (/^.*\.bb\z/s) {
        my $fileinfo = new Globus::Coverage::File();
        my $in;
        local(*PIPE);

        open(PIPE, "gcov -f -p -l -b -o .libs \"$_\"|") || return;

        while ($in = <PIPE>) {
            chomp;

            if ($in =~ m/([0-9.]+)% of (\d+) lines executed in (\S+) (\S+)/) {
                my $type = $3;
                my $name = $4;
                my $statements = $2;
                my $covered = sprintf('%.0f', ($2 * $1 * 0.01));

                if ($type eq 'function') {
                    my $funcinfo = $fileinfo->function($name);

                    $funcinfo->statement_coverage($statements, $covered);
                } elsif ($type eq 'file') {
                    $fileinfo->statement_coverage($statements, $covered);
                }
            } elsif ($in =~ m/No executable lines in (\S+) (\S+)/) {
                my $type = $1;
                my $name = $2;

                if ($type eq 'function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->statement_coverage(0, 0);
                } elsif ($type eq 'file') {
                    $fileinfo->statement_coverage(0, 0);
                }
            } elsif ($in =~ m/([0-9.]+)% of (\d+) branches taken at least once in (\S+) (\S+)/) {
                my $type = $3;
                my $name = $4;
                my $branches = $2;
                my $covered = sprintf('%.0f', ($2 * $1 * 0.01));

                if ($type eq 'function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->branch_coverage($branches, $covered);
                } elsif ($type = 'file') {
                    $fileinfo->branch_coverage($branches, $covered);
                }
            } elsif ($in =~ m/No branches in (\S+) (\S+)/) {
                my $type = $1;
                my $name = $2;
                if ($type eq 'function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->branch_coverage(0, 0);
                } elsif ($type eq 'file') {
                    $fileinfo->branch_coverage(0, 0);
                }
            } elsif ($in =~ m/Creating (\S+)\.$/) {
                my $sourcename = $1;
                my $gcovfile = $1;
                $sourcename =~ s/.*##(\S*).gcov/$1/;
                $fileinfo->name($sourcename);
                $package_info->file($sourcename, $fileinfo);
                $self->parse_gcov_file($fileinfo, "$gcovfile");

                $fileinfo = new Globus::Coverage::File();
            }
        }
    }
}

sub find_basic_block4
{
    my $self = shift;
    my $type;
    my $name;
    my $package_info = $self->{PACKAGE};

    if (/^\.libs\z/s && ($File::Find::prune = 1))
    {
        return;
    }
    if (/(^.*\.gcno\z)/s) {
        my $fileinfo = new Globus::Coverage::File();
        my $in;
        local(*PIPE);

        open(PIPE, "gcov -f -p -l -b -o .libs \"$_\" | sed -e s\"/Function '_/Function '__/\" | c++filt|") || return;

        while ($in = <PIPE>) {
            chomp;

            if ($in =~ m/(Function|File) '([^']+)'/)
            {
                $type = $1;
                $name = $2;
            }
            elsif ($in =~ m/Lines executed:([0-9.]+)% of (\d+)/) {
                my $statements = $2;
                my $covered = sprintf('%.0f', ($2 * $1 * 0.01));

                if ($type eq 'Function') {
                    my $funcinfo = $fileinfo->function($name);

                    $funcinfo->statement_coverage($statements, $covered);
                } elsif ($type eq 'File') {
                    $fileinfo->statement_coverage($statements, $covered);
                }
            } elsif ($in =~ m/No executable lines/) {
                if ($type eq 'Function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->statement_coverage(0, 0);
                } elsif ($type eq 'File') {
                    $fileinfo->statement_coverage(0, 0);
                }
            } elsif ($in =~ m/Branches executed:([0-9.]+)% of (\d+)/) {
                my $branches = $2;
                my $covered = sprintf('%.0f', ($2 * $1 * 0.01));

                if ($type eq 'Function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->branch_coverage($branches, $covered);
                } elsif ($type = 'File') {
                    $fileinfo->branch_coverage($branches, $covered);
                }
            } elsif ($in =~ m/No branches/) {
                if ($type eq 'Function') {
                    my $funcinfo = $fileinfo->function($name);
                    $funcinfo->branch_coverage(0, 0);
                } elsif ($type eq 'File') {
                    $fileinfo->branch_coverage(0, 0);
                }
            } elsif ($in =~ m/([^:]*):creating '(\S+)'$/) {
                my $sourcename = $1;
                my $gcovfile = $2;

                if ($sourcename =~ m|^/| || 
                    $sourcename !~ m/\.(c|cpp)$/) {
                    next;
                }

                $sourcename =~ s|/|#|g;

                $fileinfo->name($sourcename);
                $package_info->file($sourcename, $fileinfo);
                $self->parse_gcov_file($fileinfo, "$gcovfile");

                $fileinfo = new Globus::Coverage::File();
                $type = '';
                $name = '';
            }
        }
    }
}

# returns reference to a hash containing the keys
# SUMMARY -> link to overview report containing %s of functions and files
#            reached
# SOURCE -> source filename
# LINES -> array reference (indexed by line number) containing
#          hash reference containing of COUNT -> # times executed 
#          and LINE -> source code line values
sub parse_gcov_file {
    my $self = shift;
    my $fileinfo = shift;
    my $report_file = shift;
    my $in;

    local(*GCOV_FILE);

    open(GCOV_FILE, "<$report_file");

    while ($in = <GCOV_FILE>) {
        my @fields = split(/:/, $in, 3);
        if (int($fields[1]) == 0) {
            if ($fields[2] =~ '^Source:') {
                my $filename = (split(/:/, $fields[2], 2))[1];
                local(*SOURCE);

                open(SOURCE, "<$filename");
                $fileinfo->source(join(//, <SOURCE>));
                close(SOURCE);
            }
        } else {
            if ($fields[0] =~ m/#####/) {
                $fileinfo->line_coverage($fields[1], 0);
            } elsif ($fields[0] =~ m/-/) {
                $fileinfo->line_coverage($fields[1], '-');
            } elsif ($fields[0] !~ m/-/) {
                $fileinfo->line_coverage($fields[1], int($fields[0]));
            }
        }
    }
    close (GCOV_FILE);
}

1;
