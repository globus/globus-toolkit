package Globus::GRAM::ExtensionsHandler;

use strict;
use XML::Parser;
use Switch;

############ define element scope constants here ############
my ($UNKNOWN_SCOPE,   $EXTENSIONS,    $EXTRA_ARGUMENTS)
 = ("unknown_scope",  "extensions",   "extraArguments");

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

#print "Tag: $tagName\n";

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

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    my $currentScope = $scope[$#scope];
    my $parentScope = $scope[$#scope-1];

    if ($#scope eq 1)
    {
        #just left extension element
        if ($self->{SUB_ELEMENT_COUNT} eq 0)
        {
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
                        push(@$newValue, $self->{CDATA});
                    }
                    else
                    {
                        $newValue = [ $oldValue ];
                        push(@$newValue, $self->{CDATA});
                    }
                }
                else
                {
                    $newValue = [ $self->{CDATA} ];
                }
                $self->{JOB_DESCRIPTION}->add($tagName, $newValue);
            }
#$self->{JOB_DESCRIPTION}->save();
        }

        $self->{SUB_ELEMENT_COUNT} = 0;
        $self->{LAST_EXTENSION} = $parentScope;
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

    if ($currentScope eq $EXTRA_ARGUMENTS)
    {
        $self->extraArguments($char);
    }
    elsif ($parentScope eq $EXTENSIONS)
    {
        $self->{CDATA} .= $char;
    }
}

############ define element handling subs here ############
sub extraArguments
{
    my $self = shift;
    my $text = shift;

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    if ($scope[$#scope-1] == $EXTENSIONS)
    {
        my @arguments = $self->{JOB_DESCRIPTION}->arguments();
        my @parsed_arguments = split(' ', $text);
        push(@arguments, @parsed_arguments);
        $self->{JOB_DESCRIPTION}->add("arguments", \@arguments);
    }
}

1;
