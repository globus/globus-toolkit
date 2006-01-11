package Grid::GPT::V1::Definitions;

use strict;
use Carp;


require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS @package_types 
		  @dependencies %src2bin_dependencies %noflavor_pkg_types
%installation_dependencies);

use Data::Dumper;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);
@EXPORT      = qw(&open_metadata_file &func2 &func4);
%EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

@package_types = ("data", "dev", "doc", "pgm", "pgm_static", "rtl", "src");

@dependencies = ("Source_Dependencies","Compile_Dependencies","Runtime_Dependencies",
		    "Runtime_Link_Dependencies","Regeneration_Dependencies",
		    "Build_Link_Dependencies");

%src2bin_dependencies = 
  (
   'Compile_Dependencies' => {
			      pgm=> undef,
			      pgm_static=> undef,
			      dev=> undef,
			      data=> undef,
			      doc=> undef,
			      rtl=> undef
			     },
   'Source_Link_Dependencies' => {
				  pgm=>	
				  {src => 'pgm_Link_Dependencies' ,bin => 'Runtime_Link_Dependencies'},
				  pgm_static=> 
				  {src => 'pgm_Link_Dependencies' ,bin => 'Regeneration_Dependencies'},
				  dev=> 
				  {src => 'lib_Link_Dependencies' ,bin => 'Build_Link_Dependencies'},
				  data=> 
				  {src => undef ,bin => undef},
				  doc=> 
				  {src => undef ,bin => undef},
				  rtl=> 
				  {src => 'lib_Link_Dependencies' ,bin => 'Runtime_Link_Dependencies'},
				 },         
   'Source_Runtime_Dependencies' =>{
				    pgm=> 
				    {src => 'pgm_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    pgm_static=> 
				    {src => 'pgm_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    dev=> 
				    {src => 'lib_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    data=> 
				    {src => 'data_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    doc=> 
				    {src => 'doc_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    hdr=> 
				    {src => 'doc_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				    rtl=> 
				    {src => 'lib_Runtime_Dependencies' ,bin => 'Runtime_Dependencies'},
				   }

  );

%installation_dependencies =
(
	 'pgm'=> [ 'Runtime_Dependencies', 'Runtime_Link_Dependencies'],
     'pgm_static'=> ['Runtime_Dependencies'],
     'dev'=> ['Runtime_Dependencies'],
     'data'=> ['Runtime_Dependencies'],
     'doc'=> ['Runtime_Dependencies'],
     'rtl'=> ['Runtime_Dependencies', 'Runtime_Link_Dependencies']        
	
);

%noflavor_pkg_types = ("data" => 1, "doc" => 1);

#sub new {
#    my $class  = shift;
#    my $self  = {
#        %definitions,
#    };
#    bless $self, $class;
#    return $self;
#} 
	

#sub AUTOLOAD {
#	use vars qw($AUTOLOAD);
#    my $self = shift;
#    my $type = ref($self) || croak "$self is not an object";
#    my $name = $AUTOLOAD;
#    $name =~ s/.*://;   # strip fully-qualified portion
#    unless (exists $self->{$name} ) {
#        croak "Can't access `$name' field in object of class $type";
#    } 
#    if (@_) {
#        return $self->{$name} = shift;
#    } else {
#        return $self->{$name};
#    } 
#}




END { }       # module clean-up code here (global destructor)
1;
