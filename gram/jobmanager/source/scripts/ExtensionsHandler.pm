package Globus::GRAM::ExtensionsHandler;

use strict;
use XML::Parser;
use Switch;

############ define element scope constants here ############
my ($SCOPE_UNKNOWN, $SCOPE_EXTENSIONS,  $SCOPE_EXTRA_ARGUMENTS)
 = (0,              1,                  2);

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $description = shift;
    my $self  = {};

    $self->{SCOPE} = [];

    $self->{JOB_DESCRIPTION} = $description;

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

    my $description = $self->{JOB_DESCRIPTION};

    switch ($tagName)
    {
        case /extensions/ { $self->pushScope($SCOPE_EXTENSIONS) }
        case /extraArguments/ { $self->pushScope($SCOPE_EXTRA_ARGUMENTS) }
        else { $self->pushScope($SCOPE_UNKNOWN) }
    }
}

sub EndTag
{
    my $self = shift;
    my $expat = shift;
    my $tagName = shift;

    switch ($tagName)
    {
        case /extensions/ { $self->popScope() }
        case /extraArguments/ { $self->popScope() }
        else { $self->popScope() }
    }
}

sub Char
{
    my $self = shift;
    my $expat = shift;
    my $char = shift;

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    my $currentScope = $scope[$#scope];

    if ($currentScope == $SCOPE_EXTRA_ARGUMENTS)
    {
        $self->extraArguments($char);
    }
}

############ define element handling subs here ############
sub extraArguments
{
    my $self = shift;
    my $text = shift;

    my $scope = $self->{SCOPE};
    my @scope = @$scope;
    if ($scope[$#scope-1] eq $SCOPE_EXTENSIONS)
    {
        my @arguments = $self->{JOB_DESCRIPTION}->arguments();
        my @parsed_arguments = split(' ', $text);
        push(@arguments, @parsed_arguments);
        $self->{JOB_DESCRIPTION}->add("arguments", \@arguments);

        @arguments = $self->{JOB_DESCRIPTION}->arguments();
    }
}

1;
