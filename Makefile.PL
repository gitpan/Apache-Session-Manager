use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Apache::Session::Manager',
    'VERSION_FROM'	=> 'Manager.pm', # finds $VERSION
    'PREREQ_PM'		=> {
		mod_perl				=>	'1.27',
		Apache::Request	=>	'1.0',
		Apache::Cookie		=>	'1.0',
		Apache::Session	=>	'1.54',
		Digest::MD5			=>	'2.20'}, 
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'Manager.pm', # retrieve abstract from module
       AUTHOR     => 'Clinton Gormley <develop@drtech.co.uk>') : ()),
);
