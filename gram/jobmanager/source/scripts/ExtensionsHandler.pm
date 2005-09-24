package Globus::GRAM::ExtensionsHandler;

use strict;
use XML::Parser;
use Switch;

############ define element scope constants here ############
my ($UNKNOWN_SCOPE,   $EXTENSIONS)
 = ("unknown_scope",  "extensions");

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $jmClass = shift;
    my $description = shift;
    my $self  = {};

    $jmClass =~ s/Globus::GRAM::JobManager:://;
    $self->{RM_NAME} = $jmClass;
    $self->{JOB_DESCRIPTION} = $description;

    $self->{SCOPE} = [];
    $self->{SUB_ELEMENT_COUNT} = 0;

    bless $self, $class;

    if (defined($description->extensions()))
    {
        my $extParser = new XML::Parser(Handlers => {
            Start       => sub { $self->StartTag(@_); },
            End         => sub { $self->EndTag(@_); },
            Char        => sub { $self->Char(@_); } });
        my $extDoc = "<extensions>"
                   . $description->extensions()
                   . "</extensions>";
        $extParser->parse($extDoc);
    }

    return $self;
}

sub pushScope
{
    my $self = shift;
    my $value = shift;

    my $scope = $self->{SCOPE};
    push(@$scope, $value);
}

sub popScope
{
    my $self = shift;

    my $scope = $self->{SCOPE};
    pop(@$scope);
}

sub StartTag
{
    my $self = shift;
    my $expat = shift;
    my $tagName = shift;

    $self->log("Start Tag: $tagName");

    # collect attributes for this element
    my %attributes = { };
    my $attrName = shift;
    while (defined $attrName)
    {
        my $attrValue = shift;
        $attributes{$attrName} = $attrValue;

        $attrName = shift;
    }
    $self->{ATTRIBUTES} = \%attributes;

    my @keys = keys(%attributes);
    if ($#keys >= 0)
    {
        my $msg = "Collected the following attributes for element $tagName:\n";
        foreach my $key (@keys)
        {
            $msg .= "\t$key => $attributes{$key}\n";
        }
        $self->log($msg);
    }

    my $description = $self->{JOB_DESCRIPTION};

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    if ($#scope gt 0)
    {
        #just entered sub-extension-element element
        $self->{SUB_ELEMENT_COUNT}++;
    }
    $self->pushScope($tagName);
}

sub EndTag
{
    my $self = shift;
    my $expat = shift;
    my $tagName = shift;

    $self->log("End Tag: $tagName");

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    my $currentScope = $scope[$#scope];
    my $parentScope = $scope[$#scope-1];

    if ($#scope == 1)
    {
        #just left extension element
        $self->log("Processing extension element $tagName");

        if ($self->{SUB_ELEMENT_COUNT} eq 0)
        {
            $self->log("$tagName has no sub-elements");

            #leaving element with no sub-elements
            if (length($self->{CDATA}) and ($self->{CDATA} =~ /\S/))
            {
                #saved non-whitespace CDATA, so trim and set as attr
                $self->{CDATA} =~ s/^\s+//;
                $self->{CDATA} =~ s/\s+$//;

                my $oldValue = $self->{JOB_DESCRIPTION}->get($tagName);
                my $newValue;
                if (defined($oldValue))
                {
                    if (ref($oldValue) eq 'ARRAY')
                    {
                        $newValue = $oldValue;
                    }
                    else
                    {
                        $newValue = [ $oldValue ];
                    }

                    my $attributes = $self->{ATTRIBUTES};
                    my $name = %$attributes->{name};
                    if (defined $name)
                    {
                        push(@$newValue, [$name, $self->{CDATA}]);
                    }
                    else
                    {
                        push(@$newValue, $self->{CDATA});
                    }
                }
                else
                {
                    my $attributes = $self->{ATTRIBUTES};
                    my $name = %$attributes->{name};
                    if (defined $name)
                    {
                        $newValue = [ [ $name, $self->{CDATA} ] ];
                    }
                    else
                    {
                        $newValue = [ $self->{CDATA} ];
                    }
                }

                my $logIsOpen = 0;
                if(defined($self->{JOB_DESCRIPTION}->logfile()))
                {
                    $logIsOpen = 1;
                }

                $self->{JOB_DESCRIPTION}->add($tagName, $newValue);

                if(    (not $logIsOpen)
                   and defined($self->{JOB_DESCRIPTION}->logfile()))
                {
                    local(*FH);
                    open(FH, '>>'. $self->{JOB_DESCRIPTION}->logfile());
                    select((select(FH),$|=1)[$[]);
                    $self->{log} = *FH;
                }
#$self->{JOB_DESCRIPTION}->save();
            }
        }
        else
        {
            #leaving element with one or more sub-elements
            $self->log("$tagName has $self->{SUB_ELEMENT_COUNT} sub-elements");

            #TODO support other resource managers
            if (    ($currentScope eq 'resourceAllocationGroup')
                   and ($self->{RM_NAME} eq 'pbs'))
            {
                #just left a resourceAllocationGroup element
                $self->log("converting $tagName to #PBS -l nodes=...");

                my $hostType = $self->{HOST_TYPE};
                my $hostCount = $self->{HOST_COUNT};
                my $hostNames = $self->{HOST_NAMES};
                my $processCount = $self->{PROCESS_COUNT};
                my $processesPerHost = $self->{PROCESSES_PER_NODE};

                my $nodes = $self->{JOB_DESCRIPTION}->nodes();
                if (defined $nodes)
                {
                    # already parsed a resourceAllocationGroup, so append
                    $self->log("nodes exists...appending with \'+\'\n");
                    $nodes .= "+";
                }
                else
                {
                    # first resourceAllocationGroup
                    $self->log("no nodes exists...\n");
                    $nodes = "";
                }

                if (defined $processCount)
                {
                    $self->log("Processing processCount\n");

                    if (defined $hostType)
                    {
                        $self->log("Processing hostType\n");

                        if (defined $hostCount)
                        {
                            $self->log("Processing hostCount\n");

                            # divide total processes among the nodes
                            my $ppn = $processCount / $hostCount;

                            $nodes .= "$processCount:$hostType:ppn=$ppn";
                        }
                        else
                        {
                            # only one node, so it gets all the processes
                            $nodes .= "$hostType:ppn=$processCount";
                        }
                    }
                    elsif (defined $hostNames)
                    {
                        my @names = @$hostNames;
                        $self->log("Processing hostName list\n");

                        # divide total processes among the nodes
                        my $hostCount = $#names + 1;
                        my $ppn = $processCount / $hostCount;

                        foreach my $name (@names)
                        {
                            $nodes .= "$name:ppn=$ppn+";
                        }
                        $nodes =~ s/\+$//;
                    }
                    else
                    {
                        $nodes .= "1:ppn=$processCount";
                    }
                }
                elsif (defined $processesPerHost)
                {
                    $self->log("Processing processesPerHost\n");

                    if (defined $hostType)
                    {
                        $self->log("Processing hostType\n");

                        if (defined $hostCount)
                        {
                            $self->log("Processing hostCount\n");

                            $nodes .= "$hostCount"
                                   . ":$hostType"
                                   . ":ppn=$processesPerHost";
                        }
                        else
                        {
                            $nodes .= "$hostType:ppn=$processesPerHost";
                        }
                    }
                    elsif (defined $hostNames)
                    {
                        $self->log("Processing hostNames list\n");

                        my @names = @$hostNames;

                        foreach my $name (@names)
                        {
                            $nodes .= "$name:ppn=$processesPerHost+";
                        }
                        $nodes =~ s/\+$//;
                    }
                    else
                    {
                        $nodes .= "ppn=$processesPerHost";
                    }
                }

                $nodes =~ s/\s+//g;

                $self->log("Adding #PBS -l nodes=$nodes\n");

                $self->{JOB_DESCRIPTION}->add("nodes", $nodes);
#$self->{JOB_DESCRIPTION}->save();

                # reset values in case we get another resourceAllocationGroup
                $self->{HOST_TYPE} = undef;
                $self->{HOST_COUNT} = undef;
                $self->{HOST_NAMES} = undef;
                $self->{PROCESS_COUNT} = undef;
                $self->{PROCESSES_PER_NODE} = undef;
            }
        }

        $self->{SUB_ELEMENT_COUNT} = 0;
        $self->{LAST_EXTENSION} = $parentScope;
    }
    elsif ($#scope == 2)
    {
        if ($parentScope eq 'resourceAllocationGroup')
        {
            if ($currentScope eq 'hostType')
            {
                $self->log("Parsing hostType\n");
                $self->{HOST_TYPE} .= $self->{CDATA};
            }
            elsif ($currentScope eq 'hostCount')
            {
                $self->log("Parsing hostCount\n");
                $self->{HOST_COUNT} .= $self->{CDATA};
            }
            elsif ($currentScope eq 'hostName')
            {
                if ($self->{CDATA} =~ /\S/)
                {
                    $self->log("Parsing hostName\n");

                    my $hostNames = $self->{HOST_NAMES};
                    if (not defined $hostNames)
                    {
                        $self->{HOST_NAMES} = [ ];
                        $hostNames = $self->{HOST_NAMES}
                    }

                    push(@$hostNames, $self->{CDATA});

                    $self->log("New host names list: @$hostNames\n");
                }
            }
            elsif ($currentScope eq 'processCount')
            {
                $self->log("Parsing processCount\n");
                $self->{PROCESS_COUNT} = $self->{CDATA};
            }
            elsif ($currentScope eq 'processesPerHost')
            {
                $self->log("Parsing processesPerHost\n");
                $self->{PROCESSES_PER_NODE} = $self->{CDATA};
            }
        }
    }

    $self->{CDATA} = "";
    $self->{LAST_EXTENSION} = $self->popScope();
}

sub Char
{
    my $self = shift;
    my $expat = shift;
    my $char = shift;

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    my $currentScope = $scope[$#scope];
    my $parentScope = $scope[$#scope-1];

    $self->{CDATA} .= $char;
}

sub log
{
    my $self = shift;

    if(exists($self->{log}))
    {
        my $fh = $self->{log};
        print $fh scalar(localtime(time)), " EXTENSIONS_HANDLER: ", @_, "\n";
    }

    return;
}

1;
