package Grid::GPT::V1::XML;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
#use Data::Dumper;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);
@EXPORT      = qw();
%EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

# your exported package globals go here,
# as well as any optionally exported functions
@EXPORT_OK   = qw();

use vars qw();
# non-exported package globals go here
use vars      qw();

# initialize package globals, first exported ones

# then the others (which are still accessible as $Some::Module::stuff)

# all file-scoped lexicals must be created before
# the functions below that use them.

# file-private lexicals go here

# here's a file-private function as a closure,
# callable as &$priv_func.

# make all your functions, whether exported or not;
# remember to put something interesting in the {} stubs


sub new {
    my $that  = shift;
    my $class = ref($that) || $that;
    my $self  = {};
    bless $self, $class;
    return $self;
}

sub read {
  my ($self, $string) = @_;
  my $filename;
  my @lines;
  if ($string =~ m{<.*?>}s  or  ref($string)) {
  	@lines= $string;	
	}else{
		$filename=$string;
  		open (FILE, "$filename") or die "ERROR: cannot open $filename: $!\n";
  		@lines = <FILE>;
  }
  my $lineno = 0;
  my $buffer = "";
  my @tagstack;
  my $leftover;
  for my $l (@lines) {
    $lineno++;
    $l = "$leftover $l" if defined $leftover;
#    print "line: $l";
    my $lastmatch = 0;
    while ($l =~ m!([^<]*)<([^>]+)>!g) {
      my $contents = $1;
      my $tagcontents = $2;
      $lastmatch = pos($l);
      if ( $tagcontents =~ m!\?xml\s+!) {
	next;
      }

      if ( $tagcontents =~ m!\!\s*DOCTYPE\s+(\w+)\s+SYSTEM\s*\"([^\"]+)\"!) {
	$self->doctype($1, $2);
	next;
      }

      if ($tagcontents =~ m!^\s*/\s*(.+)$!) {
	# process an endtag
	my $tag = $1;
	$tag =~ s!(\S+)\s*$!$1!;
	if ($tag =~ m!\w\s+\w!) {
	  warn "ERROR: $lineno - Ending tag <$tag> cannot contain any spaces\n";
	  push @{$self->{'errors'}}, 
	  "ERROR: $lineno - Ending tag <$tag> cannot contain any spaces";
	}
	my $currenttag = pop @tagstack;
	if ($tag ne $currenttag->{'name'}) {
	  my $found = 0;
	  my @tagunwind;
	  push @tagunwind, $currenttag;	  
	  for my $t (reverse @tagstack) {
#	    print "unwinding tag $t->{'name'}\n";
	    if ($tag eq $t->{'name'}) {
	      $found++;
	      last;
	    }
	    push @tagunwind, $t;
	  }
	  if (!$found) {
	    warn "ERROR: $lineno - Ending tag <$tag> does not have a corresponding start tag\n"; 
	    push @{$self->{'errors'}}, 
	    "ERROR: $lineno - Ending tag <$tag> does not have a corresponding start tag";
	  } else {
	    warn "ERROR: $lineno - Ending tag <$tag> is out of sequence\n"; 
	    push @{$self->{'errors'}}, 
	    "ERROR: $lineno - Ending tag <$tag>  is out of sequence\n";
	    
	  }
	  
	  for my $t (@tagunwind) {
	    warn "ERROR: $t->{'lineno'} - Tag <$t->{'name'}> needs end tag before <$tag> at line $lineno\n"; 
	    push @{$self->{'errors'}}, 
	    "ERROR: $t->{'lineno'} - Tag <$t->{'name'}> needs end tag before <$tag> at line $lineno"; 
	  }

	}
	push @{$currenttag->{'contents'}}, $contents if defined $contents;
	push @{$tagstack[-1]->{'contents'}}, $currenttag if @tagstack;
      }

      else {
	# process a start tag
	$tagcontents =~ m!^\s*(\w+)!;
	my $tagsave = $tagcontents;
	my $starttag = $1;
	my $emptytag = 0;
	$emptytag = 1 if $tagcontents =~ s!/\s*$!!;
	if ($starttag eq "") {
	  warn "ERROR: $lineno - Starting tag <$tagcontents> is malformed\n";
	  push @{$self->{'errors'}}, 
	  "ERROR: $lineno - Starting tag <$tagcontents> is malformed";	
	}
	my $tagobj = create_tag($starttag);
	$tagobj->{'lineno'} = $lineno;
	#The first tag encountered is the root tag
	if (!defined ($self->{'roottag'})) {
	  $self->{'roottag'} = $tagobj;
	}

	$tagcontents =~ s!$starttag!!;
	while ($tagcontents =~ s!(\w+)\s*=\s*\"([^\"]+)\"!!) {
	  $tagobj->{'attributes'}->{$1} = $2; 
	}
	if ($tagcontents =~ m!\S!) {
	  warn "ERROR: $lineno - Tag <$tagsave> is malformed\n";
	  push @{$self->{'errors'}}, 
	  "ERROR: $lineno -  Tag <$tagsave> is malformed";
	}


	if (@tagstack) {
	  push @{$tagstack[-1]->{'contents'}}, $contents if $contents ne "";
	}
	if ($emptytag) {
	  if (! @tagstack) {
	    warn "ERROR: $lineno - can't start a document with an empty tag <$tagcontents>\n";
	    push @{$self->{'errors'}}, 
	    "ERROR: $lineno - can't start a document with an empty tag <$tagcontents>";
	  }
	  push @{$tagstack[-1]->{'contents'}}, $tagobj;
	} else {
	  push @tagstack, $tagobj;	  
	}
      }
    }

    $leftover = substr($l,$lastmatch);
#    my $i = 0;
#    for (@tagstack) {
#    print "tag: $i: ", Dumper($_);
#    $i++;
#    }
  }


  for my $t (@tagstack) {
   warn "ERROR: $t->{'lineno'} - Tag <$t->{'name'}> does not have an end tag\n"; 
   push @{$self->{'errors'}}, 
   "ERROR: $t->{'lineno'} - Tag <$t->{'name'}> does not have an end tag"; 
  }
#  print Dumper($self);
}

sub doctype 
  {
    my ($self, $doctype, $system) = @_;
    $self->{'doctype'} = $doctype;
    $self->{'system'} = $system;
}
sub create_tag {
  my ($name) = @_;
 return { name => $name, attributes => {}, contents => []}
}

sub startTag {
  my ($self, $name, %attrs) = @_;
  my $tag = create_tag($name);
  $tag->{'attributes'} = \%attrs;
  if (defined $self->{'tagstack'}) {
    push @{$self->{'tagstack'}->[-1]->{'contents'}}, $tag;
  } else {
    $self->{'tagstack'} = [];
    $self->{'roottag'} = $tag;
  }
  push @{$self->{'tagstack'}},$tag;
}

sub emptyTag {
  my ($self, $name, %attrs) = @_;
  my $tag = create_tag($name);
  $tag->{'attributes'} = \%attrs;
  if (defined $self->{'tagstack'}) {
    push @{$self->{'tagstack'}->[-1]->{'contents'}}, $tag;
  } 
}
sub dataElement {
  my ($self, $name, $contents, %attrs) = @_;
  my $tag = create_tag($name);
  $tag->{'attributes'} = \%attrs;
  push @{$tag->{'contents'}}, $contents;
  if (defined $self->{'tagstack'}) {
    push @{$self->{'tagstack'}->[-1]->{'contents'}}, $tag;
  }

}

sub endTag {
  my ($self, $name) = @_;
  die "ERROR: no valid tags to end with $name\n" if ! defined $self->{'tagstack'};
  my $tag = pop @{$self->{'tagstack'}};
  die "ERROR: mismatched start tag $tag->{'name'} and end tag $name\n" if  $tag->{'name'} ne $name;

}

sub characters {
  my ($self, $contents) = @_;
  die "ERROR: no valid tags for contents $contents\n" if ! defined $self->{'tagstack'};
  push @{$self->{'tagstack'}->[-1]->{'contents'}}, $contents;
}

sub close_tag {
  my ($self, $filename) = @_;
  die "ERROR: no valid tags to close\n" if ! defined $self->{'tagstack'};
  my $roottag = $self->{'tagstack'}->[0];
  $self->{$roottag->{'name'}} = $roottag;
  $self->{'roottag'} = $roottag->{'name'};
}

sub write {
  my ($self, $filename) = @_;
  local *FILE;
  if (defined ($filename)) {
    open (FILE, ">$filename") or die "ERROR could not write $filename\n";
    $self->{'FILE'} = \*FILE;
  } else {
    $self->{'FILE'} = \*STDOUT;
  }
  my $root = $self->{'roottag'};

  print FILE '<?xml version="1.0" encoding="UTF-8"?>
';
  print FILE "<!DOCTYPE $self->{'doctype'} SYSTEM \"$self->{'system'}\">\n";

  $self->write_tag($root);
  print FILE "\n";
  close(*FILE);
}

sub write_tag {
  my ($self, $tag) = @_;
  local *FILE = *{$self->{'FILE'}};
  
  print FILE "<$tag->{'name'} ";

  for my $a (sort keys %{$tag->{attributes}}) {
    print FILE "$a=\"$tag->{attributes}->{$a}\" ";
  }

  if (@{$tag->{'contents'}} == 0) {
    print FILE "/>";
    return;
  } else {
    print FILE ">";    
  }

  for my $c (@{$tag->{'contents'}}) {
#    use Data::Dumper;
#    print "XML undefined content: ", Dumper $tag  if ! defined $c;
    if (ref($c) eq 'HASH') {
#      print "<$tag->{'name'}>\n";
      $self->write_tag($c);
    } else {
      print FILE "$c";
    }
  }

  print FILE "</$tag->{'name'}>";
}


	
END { }       # module clean-up code here (global destructor)

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::V1::XML - Perl extension for parsing and writing XML files

=head1 SYNOPSIS

  use Grid::GPT::V1::XML;
  my $xml = new Grid::GPT::V1::XML;

  $xml>read('src_metadata.xml');

  $root = $xml->{'roottag'};

  print "For tag $root->{'name'}\n";

  for my $a ( sort keys %{$root->{'attributes'}}) {
     print "Attribute $a is set to $root->{'attributes'}->{$a}\n";
  }

=head1 DESCRIPTION

I<Grid::GPT::V1::XML> is used to read and write xml files along the lines
of XML::Simple and XML::Writer although without using the expat
library.  Any simularity with the output methods of XML::Writer is
purely intentional.


=head1 Perl Representation of XML Tags.

I<Grid::GPT::V1::XML> Stores the pieces of the XML file in a hash
structure consisting of tag "objects".  Each object consists of the
following structure:

=over 4

=item name

Name of the tag

=item attributes

A hash containing the attributes of a tag.  Each attribute is keyed by
name and points to its value.

=item contents

A list that contents strings or other tag objects in order of occurance.

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::V1::XML> object.

=item read(filename)

Parse an xml file. Transform the file into its perl representation.

=item doctype(doctype, system)

Sets the doctype and system values for a document.

=item startTag(tagname[, attr1 => value1, attr2 => value2...])

Starts a new tag object.  This object then becomes part of the
contents of the last tag started.

=item emptyTag(tagname[, attr1 => value1, attr2 => value2...])

Add an empty tag to the last tag started.

=item dataElement(tagname, contents[, attr1 => value1, attr2 => value2...])

Add a non-empty tag to the last tag started.

=item endTag(tagname)

End the last tag started.  If tagname does not match the this tag then
the script dies.

=item characters(contents)

Add content to the last tag started.

=item close_tag

End the building of the XML document.

=item write(filename)

Transform the perl representation into XML and write it to the file.
Note that all tags that do not have content are trnsformed into empty
tags.

=back

=head1 Example

Given the following XML:

  <foo_tag life="short" fun="much">
   Are we there yet
   <fum_tag death="iminent" temper="short"/>
  </foo_tag>

The Perl representation looks like this:

  VAR1 {
        'name' => 'foo_tag',
        'attributes' => {
                         'life' => 'short',
                         'fun' => 'much',
                         },
        'contents' => [
                      'Are we there yet',
                      {
                      'name' => 'fum_tag',
                      'attributes' => {
                                      'death' => 'iminent',
                                      'temper' => 'short',
                                      }, 
                      'contents' => [],
                      },
                      ],
       }


To create the XML do the following:

   startTag("foo_tag", life => 'short', fun => 'much');
   characters("Are we there yet"); 
   emptyTag("fum_tag", death => "iminent", temper => "short");

=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1).

=cut
