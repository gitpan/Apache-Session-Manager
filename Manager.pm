package Apache::Session::Manager;

use strict;
use warnings;
use warnings::register;
use 5.005;

use Apache::Request();
use Apache::Session::Flex();
use Apache::Cookie();
use Digest::MD5 qw(md5_hex);

our $VERSION = '0.03';


#============================ Set class variables  and constants ==========================================

use constant DEBUG => 0;													# DEBUG = 0 means debug code doesn't get compiled
#use Data::Dumper;

use constant NOCOOKIES => 0;											# Defines constants to represent which cookies to bake
use constant COOKIES => 1;
use constant SECURE_COOKIES => 2;

use constant SRCSTRING => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY0123456789';
																							# Used by the generate random key methods below
								
our $errstr;																				# Will contain any class errors

my %Config = (
	Session_Mngr			=> undef,											# Will hold Apache::Session::Flex manager details;
	Session_Expiry			=> 60*15,											# Default session inactivity time = 15 minutes
	Cookie_Domain 			=> '',													# Domain for which cookies will be served
	Cookie_Expiry 			=> '+1y',												# Domain for which cookies will be served
	Hash_Length 			=> 16, 												# Length of MD5 hash for SID and Secure ID
	Secret_User_Key		=> undef,											# This must be defined (pref at server startup) otherwise won't be able to recognise returning visitors
	UID_Tries					=> 20,												# Number of new UIDs that will be tried before the routine gives up
	UID_Length				=> 32,												# Length of UIDs

###### !!! THIS PACKAGE MUST BE LOADED AT SERVER STARTUP TO MAKE SURE KEYS ARE THE SAME!!!######

	Secret_Session_Key 	=> _generate_random_key(16),
	Secret_Secure_Key 	=> _generate_random_key(16),
);



#===================================
sub new {																				# Create a new Apache::Session::Manager object
#===================================
	my $proto = shift;
	my $class = ref ($proto) || $proto;

	my $apr = Apache::Request->new(shift);								# Create a new Apache::Request object

	my $self = { 
			'__cookies_to_bake'		=> 	NOCOOKIES,
			'_remember_me'			=> 	1,
			'Attached_Objects'		=>	{}
	};	
	bless($self,$class);
	$self->attach_object('request'	=> $apr);
	unless ($self->attach_object(@_)) {
		$errstr = "Problem with some of your parameters";
		 return undef;
	}
	DEBUG > 0 && print STDERR "\n*** ARM : 0 $class object created";
	return $self;

}

#===================================
sub init {																				# Populates self with objects for Cookies and Parameters
#===================================
	my $self = shift;

	DEBUG > 0 && print STDERR "\n*** ARM : 1 ".ref($self)." object initialisation";
	$self->attach_object('cookies' =>  {Apache::Cookie->new($self->request)->parse()});				# Attache new Apache::Cookie obejct
	DEBUG > 0 && print STDERR "\n Cookies : ".Dumper($self->cookies);

	$self->cookies_enabled(														# Cookies are enabled if we have found the UID or SID cookie 
			exists($self->cookies->{UID}) 
			|| exists($self->cookies->{SID}) ? 1 : 0 );

	DEBUG > 0 && print STDERR "\n*** ARM : 2 retrieving session";

	$self->_setup_session( $self->_get_session);							# Retrieve existing or get a new session, then setup session for this request

	$self->_check_logged_in;														# Check if is logged in

	DEBUG > 0 && print STDERR "\n".ref($self)." object\n".Dumper($self);
}


#===================================
sub _setup_session {																# Setup session for this request
#===================================
	my $self = shift;
	my $session = shift;
	$self->_value('session' => $session);									# Store the session in this object

	$self->_value('SID' => $session->{_session_id});					# Set SID to current session ID
	$self->_value('UID' => $session->{UID});								# Set UID to current UID
	
	DEBUG > 0 && print STDERR "\n*** ARM : 3 timestamping session";

	$self->_timestamp_session();

	DEBUG > 0 && print STDERR "\n*** ARM : 3a going to load session";

	$self->session->{username} = 
		$self->load_session($session->{UID});

	return 1;
}

#===================================
sub _get_session {																											# Retrieve existing or get a new session
#===================================
	my $self = shift;
	warnings::warn("You must ->set_session_manager() first") unless $self->config('Session_Mngr');

	DEBUG > 0 && print STDERR "\n*** ARM : 4 Looking for an SID, first in Cookies then in query/post data";
	$self->_retrieve_identifier('SID');																					# Has an SID been passed through via cookie or query string / post data?

	DEBUG > 0 && print STDERR "\n*** ARM : 5 fetching session";
	my $session = $self->_fetch_session_from_store($self->_value('SID'));							#Trying to fetch a session from the store

	unless  (defined $session) {																						# If session not found 
		DEBUG > 0 && print STDERR "\n*** ARM : 6 session not found - creating a new session";
		$session = $self->_fetch_session_from_store();														# create new session
	}

	unless (exists($session->{UID})) {																				# If no UID, then session is newly created
		DEBUG > 0 && print STDERR "\n*** ARM : 7 session has just been created : initialising newly created session";
		$self->_retrieve_identifier('UID');																				# Look for a UID passed via cookie or query string/post data

		DEBUG > 0 && print STDERR "\n*** ARM : 8 UID found : "
				.($self->_value('UID')||'undef');
		$self->_init_new_session($session);																			# Initalise a new session
		return $session
	}
																																	# If we reach here, this was an existing session
						
	my $UID =$self->request->param('UID');																		# Has a UID been passed through query string / post data
																																	# ie user has followed a link from (eg) email
																																	# then expire this session, and get a new one

	if ((time() > ($session->{last_accessed} || 0) + $self->config('Session_Expiry')) 				# If the current session has expired, OR
		|| 	($UID && $self->_check_hashed_identifier('UID',$UID) 											# If a $UID has been passed through in the query string 
				&& $UID ne $session->{UID})) {																		# which is different from the session UID (ie change user)

		DEBUG > 0 && print STDERR "\n*** ARM : 9 session has expired or UID has been passed through";
		DEBUG > 0 && print STDERR "\n*** ARM : 10 getting rid of old session";
		$self->_expire_session ($session);																			# expiring old session
		DEBUG > 0 && print STDERR "\n*** ARM : 11 then getting new session";
		$session = $self->_fetch_session_from_store();														# fetching a new session
		DEBUG > 0 && print STDERR "\n*** ARM : 12 looking for a UID (first query string, then cookie)";
		$self->_retrieve_identifier('UID');																				# get UID, first from query string, then cookie
		DEBUG > 0 && print STDERR "\n*** ARM : 13 UID found : ".($self->_value('UID')||'undef');
		DEBUG > 0 && print STDERR "\n*** ARM : 14 and initialising new session";
		$self->_init_new_session($session);																			# Initialise new session
		return $session;
	}
	return $session;
}

#===================================
sub _fetch_session_from_store {																					# Retrieve existing or create new session
#===================================
	my $self = shift;
	my $session_id = shift;																			# Possible existing session ID
	DEBUG > 0 && print STDERR "\n*** ARM : 15 fetching_session - trying to get session_id : "
			.(defined($session_id)?$session_id:'undef');
	my %session;
	eval {																									# Try to get session in eval, in case it doesn't exist
		tie %session,'Apache::Session::Flex',
				$session_id,$self->config('Session_Mngr');									# If Session ID is undef, new session is created
	};
	DEBUG > 0 && print STDERR "\n*** ARM : 16 No matching session found" if $@;
	return undef if $@;																					# No session found
	DEBUG > 0 && print STDERR "\nSession found : ".Dumper(\%session);
	return \%session
}


#===================================
sub _expire_session {																					# Removes a session from the store
#===================================
	my $self = shift;
	my $session = shift;																				# Expire current session, unless...
	my $UID = shift;																					# a different UID has been passed through

	DEBUG > 0 && print STDERR "\n*** ARM : 17 expiring the SID in db for UID : ".($UID||$session->{UID});
	my $rows = $self->update_users_SID (($UID || $session->{UID}),'') 			# Try to set the SID in the db to blank
		|| warnings::warn("Couldn't find UID : "
			.($UID || $session->{UID})." in user table");										# Warn if UID doesn't exist in db

	DEBUG > 0 && print STDERR "\n*** ARM  : 18 Rows updated : $rows";

	DEBUG > 0 && print STDERR "\n*** ARM : 19 deleting session ";
	DEBUG > 0 && print STDERR "\nSession : \n".Dumper($session);
	tied(%{$session})->delete();
}

#===================================
sub _init_new_session {																							# Initialises new session
#===================================
	my $self = shift;
	my $session = shift;

	DEBUG > 0 && print STDERR "\n*** ARM  : 20 Start of initing new session in DB";

	my $SID;

	DEBUG > 0 && print STDERR "\n*** ARM : 21 looking for old inactive session "	
		.(defined($self->_value('UID'))?$self->_value('UID'):'undef');

	if ($self->_value('UID')) {																						# If current session has an associated UID
		DEBUG > 0 && print STDERR "\n*** ARM  : 22 we have a UID";
		$SID = $self->get_users_SID($self->_value('UID'));											# Check if UID doesn't still have some active session. 

		DEBUG > 0 && print STDERR "\n*** ARM  : 23 Do we have an SID? : "	
			.(defined($SID)?$SID:'undef');
		if (defined ($SID) && length($SID)>0) {																# If user found and SID not blanked out

			DEBUG > 0 && print STDERR "\n*** ARM  : 24 We have an SID and length > 0 : $SID";
			DEBUG > 0 && print STDERR "\n*** ARM  : 25 Getting this old session";					
			if (my $new_session = $self->_fetch_session_from_store($SID)) {						# Try to retrieve that session from the Apache::Session store just in case 
				DEBUG > 0 && print STDERR "\n*** ARM  : 26 Expiring old session";
				$self->_expire_session($new_session,$self->_value('UID'));							# Expire this session
			}
		}
	}
	unless ($self->_value('UID')  && defined ($SID)) {														# If UID not set or UID not found - create new user and sets SID for that session
		DEBUG > 0 && print STDERR "\n*** ARM  : 27 No UID found - creating new UID";
		$self->_value('UID'	=> $self->_create_new_uid(													# Create new UID, with an SID of current session
				$session->{_session_id}
		));
	} else {
		DEBUG > 0 && print STDERR "\n*** ARM  : 28 UID found - updating SID to current SID : "
			.$session->{_session_id};
		my $rows = $self->update_users_SID (																# Set UID's SID to current session
				$self->_value('UID'),$session->{_session_id}) 
					|| warnings::warn("Couldn't find UID : "
							.$self->_value('UID')." in user table - bit weird");
	}

	$session->{UID} = $self->_value('UID');																		# Set Session's UID to current value
	$self->_cookies_to_bake(COOKIES);																		# Set to send standard cookies
}

#===================================
sub _create_new_uid {																								# Create a new UID in the database, and set it's SID to $SID
#===================================
	my $self = shift;
	my $SID = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 29 creating new user with SID:".(defined($SID)?$SID:'undef');
	my $tries = 0;
	my $UID;
	my $result;
	while ($tries++ < $self->config('UID_Tries')) {															# Try a new UID UID_Tries times
		$UID = substr(Digest::MD5::md5_hex(Digest::MD5::md5_hex(time(). 
			rand(). $$)), 0, $self->config('UID_Length'));
		DEBUG > 8 && print STDERR "\n*** ARM : 29a Create UID try no : $tries, UID : $UID";
		$result = $self->insert_new_UID($UID,$SID);
		last if $result>0;
	}

	DEBUG > 0 && print STDERR "\n*** ARM  : 30 UID of new user? : $UID";
	return $UID if $result;																								# Return new UID if succesful
	warnings::warn("Failed to create new uid - BUGGER!");												# Failed dismally!
	return;
}


#===================================
sub login {																													# Tries to log user in with given username and password
#===================================
	my $self = shift;
	my $username = shift;
	my $password = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 31 Retrieving username and password from db";
	my ($UID,$error) = $self->get_login_UID($username,$password);								# Check if we can find UID & password
	$self->_login_UID($UID) if $UID;
	return ($UID,$error);
}

#===================================
sub _login_UID {																										# Logs user in for passed through UID 
#===================================															# If UID is undefined, then creates a new logged in UID 
	my $self = shift;
	my $UID = shift ||'';

	DEBUG > 0 && print STDERR "\n*** ARM : 32 Starting login";

	if ($UID ne $self->_value('UID')) {																				# If new UID not same as current UID 
		DEBUG > 0 && print STDERR "\n*** ARM : 33 New UID differs from existing UID";

		my %old_session = ();

		unless ($self->session->{'_sh'}) {																			# If current user has not logged in 
			DEBUG > 0 && print STDERR "\n*** ARM : 34 Current user has not logged in, so copying existing session";
			%old_session = %{$self->session};																	# Make a copy of the current session
		}

		DEBUG > 0 && print STDERR "\n*** ARM : 35 Expiring old and getting new session";
		$self->_expire_session($self->_value('session'));													# Expire old session
		my $new_session = $self->_fetch_session_from_store();										# get new session for current user	
		
		DEBUG > 0 && print STDERR "\n*** ARM : 36 Adding old session into new session";	
		$old_session{_session_id} = $new_session->{_session_id};									# Add new session_id into copy of old session

		%{$new_session} = %old_session;																		# Copy old session to new session
		DEBUG > 0 && print STDERR "\nNew session looks like this : \n"
			. Dumper ($new_session);

		$self->_value('SID_hash' => '');																				# Clearing old SID and UID details
		$self->_value('UID_hash' => '');
		$self->_value('UID' => 	$UID);																				# if UID = undef = get new UID
		$self->_init_new_session($new_session);															# Set new session live
		$self->_setup_session($new_session);																# Setup new session for this request
	}

	DEBUG > 0 && print STDERR "\n*** ARM : 37 Setting logged in";
	$self->request_logged_in(1);																								# Set logged in flag, = user logged in for this request 
	DEBUG > 0 && print STDERR "\n*** ARM : 38 Adding hashed_secure_ID to session";
	$self->session->{'_sh'} = $self->_get_hashed_secure_ID;												# Set hashed_sh so that we know user has logged in for this session
	DEBUG > 0 && print STDERR "\n*** ARM : 39 Setting cookies to bake";
	$self->_cookies_to_bake(SECURE_COOKIES);														# Set to send secure cookies


	return $self->_value('UID');																						# return UID of logged in account
}


#===================================
sub logout	{																												# Log out current UID		
#===================================
	my $self = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 40 Logging out";
	DEBUG > 0 && print STDERR "\n*** ARM  : 41 Removing secure has from session";
	$self->session->{'_sh'} = '';																							# Remove logged in hash from session
	DEBUG > 0 && print STDERR "\n*** ARM  : 42 Setting logged in to 0";
	$self->request_logged_in(0);																								# set logged_in to 0
	DEBUG > 0 && print STDERR "\n*** ARM  : 43 Expiring session";
	$self->_expire_session($self->_value('session'));														# expire session
	DEBUG > 0 && print STDERR "\n*** ARM  : 44 Getting new session from source and setting it up";
	my $session = $self->_fetch_session_from_store();													# get new session
	$self->_init_new_session($session);																		# initialise new session
	$self->_setup_session($session);																			# setup new session
	return 1;
}

#===================================
sub remove_cookies	{																								# If user doesn't want his PC to recognise him
#===================================
	my $self = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 45 Removing cookies from computer";
	$self->_value('UID' => '');																							# Wipe out current UID
	$self->remember_me(0);																							# Only session long cookies will be set
	$self->logout();
}


#===================================
sub create_new_account {																				# Creates a new account in the database, given username, password etc
#===================================
	my $self = shift;
	my $username = shift;
	my $password = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 46 Creating new account";
	DEBUG > 0 && print STDERR "\n*** ARM  : 47 Is username available?";
	my ($UID,$error) = $self->check_username_available(									# Checks that username is available (passes through any other parameters)
			$self->_value('UID'),$username,@_);			

	DEBUG > 0 && print STDERR "\n*** ARM  : 48 UID : ".($UID || 'undef').
		", error : ",($error||'undef');
	if ($UID || $error eq 'uidtaken') {
		DEBUG > 0 && print STDERR "\n*** ARM  : 49 Logging in ";
		$UID = $self->_login_UID($UID);
		DEBUG > 0 && print STDERR "\n*** ARM  : 50 setting username and password";
		$self->set_username_and_password ($UID,$username,$password,@_);
		return $UID;
	}
	return (undef,$error);
}


###############################################################################
#THESE METHODS SHOULD BE OVERRIDEN TO TAKE CARE OF THE DATABASE STUFF
###############################################################################
#===================================
sub update_users_SID {																			## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID, $SID
	# Action : Try to set the SID for this UID to SID (blank for no session)
	# Returns : undef if couldn't find UID
	DEBUG > 0 && print STDERR "\n*** ARM  : 51 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : update_users_SID must be overridden");
}

#===================================
sub get_users_SID {																				## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID
	# Action : Try to get the SID for this UID 
	# Returns : undef if couldn't find UID, blank if UID found, but no session
	DEBUG > 0 && print STDERR "\n*** ARM  : 52 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : get_users_SID must be overridden");
}


#===================================
sub insert_new_UID {																				## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID, $SID
	# Action : Try to insert new UID and set the SID for this UID to SID
	# Returns : undef if couldn't insert UID
	DEBUG > 0 && print STDERR "\n*** ARM  : 53 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : insert_new_UID must be overridden");
}

#===================================
sub get_login_UID {																				## MUST BE OVERRIDDEN ##
#===================================
	# Params : $username, $password
	# Action : Try to find a matching username and password
	# Returns : ($UID,$error). $UID is undef if matching pair not found
	#					$error is one of 'username' or 'password' depending which was at fault
	DEBUG > 0 && print STDERR "\n*** ARM  : 54 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : get_login_UID must be overridden");
}

#===================================
sub set_username_and_password {														## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID,$username, $password, anything else
	# Action : Update username and password (and anything else) for $UID
	# Returns : true for success, false for failure
	DEBUG > 0 && print STDERR "\n*** ARM  : 55 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : set_username_and_password must be overridden");
}

#===================================
sub check_username_available {															## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID, $username, $anything else
	# Action : Check if this username (and anything else) already exists, also if current UID is already taken
	# Returns : ($UID,$error). $UID is undef if there is an error
	#					$error is 'uidtaken' if the current user's UID already has a username against it
	#					otherwise can pass back any other errors
	DEBUG > 0 && print STDERR "\n*** ARM  : 56 Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : check_username_available must be overridden");
}

#===================================
sub load_session {																				## MUST BE OVERRIDDEN ##
#===================================
	# Params : $UID
	# Action : Use this to check whether this UID already has a username
	# and to load any session data (eg name)
	# Returns : Username if found, blank if not found
	DEBUG > 0 && print STDERR "\n*** ARM  : 56b Shouldn't get here - this method should be overwritten!!!";
	warnings::warn("The method : load_session must be overridden");
}

###############################################################################


#===================================
sub _cookies_to_bake {																	# Set which cookies to bake
#===================================
	my $self = shift;
	my $val = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 57 Setting cookies to bake";
	return $self->{__cookies_to_bake} unless defined $val;					# Return the value if nothing passed through
	$self->{__cookies_to_bake} = NOCOOKIES 									# Blank out all cookies - send nothing
		if $val==NOCOOKIES;	
	$self->{__cookies_to_bake} |=$val;												# Otherwise, OR in new value
}



#===================================
sub _check_logged_in {																	# Is the user logged in for this request 
#===================================								# ie have they passed the secure hash through secure cookie or post data?
	my $self = shift;
	DEBUG > 0 && print STDERR "\n*** ARM  : 58 Is this session logged in (ie does secure hash exist?)";
	return unless $self->_value('SID') && $self->session->{'_sh'};				# Not logged in unless they have a session and a secure hash in session
	DEBUG > 0 && print STDERR "\n*** ARM  : 59 Checking for secure hash in cookies or query string";
	my $sh = $self->_retrieve_id_cookie_first('_sh');								# Look for secure hash, first from cookie then post data
	if ($sh && $sh eq $self->session->{'_sh'}) {										# If the retrieved secure hash = the one in session ....
		DEBUG > 0 && print STDERR "\n*** ARM  : 60 Setting to logged in";
		$self->request_logged_in(1);																# Logged in for this request
	} else {
		$self->request_logged_in(0);																# otherwise not
	}
}


#===================================
sub request_logged_in {																				# Gets/Sets the login flag ie is the user logged in for this request
#===================================
	my $self = shift;
	return $self->_value('logged_in' => shift) || 0;
}

#===================================
sub session_logged_in {																				# Has this session ever logged in?
#===================================
	my $self = shift;
	return (exists $self->session->{'_sh'} && $self->session->{'_sh'});				# Is true if the session secure hash flag is true
}

#===================================
sub is_registered {																						# Has this UID got an associated username ie registered account
#===================================
	my $self = shift;																						# If so, returns the username
	if (exists $self->session->{'username'}) {
		return $self->session->{'username'}}
	return undef;
}

sub _retrieve_id_param_first {																		# Look for a parameter first from query string/post data then from cookies
#===================================
	my $self = shift;
	my $param = shift;
	return $self->request->param($param) 
		|| (exists ($self->cookies->{$param}) ? $self->cookies->{$param}->value() : undef);
}

#===================================
sub _retrieve_id_cookie_first {															# Look for a parameter first from cookies then from query string/post data
#===================================
	my $self = shift;
	my $param = shift;
	if (exists ($self->cookies->{$param})) {
		return $self->cookies->{$param}->value();
	} 
	return $self->request->param($param);
}

#===================================
sub _retrieve_identifier {																	# Look for a parameter from cookies/query strings/post data and store in the object
#===================================
	my $self = shift;
	my $id = shift;

	my $val = $id eq 'SID' ? 																# A cookie SID should take precedence over a a query string SID 
			$self->_retrieve_id_cookie_first($id) 										# eg if the user sends a page on to a fried
			: $self->_retrieve_id_param_first($id);									# If a UID has been passed through in a query string (eg from a link in an email)
																									# then this should override the cookie UID value

	return unless $val &&  $self->_check_hashed_identifier($id,$val);	
	$self->_value($id => substr($val,0,-$self->config('Hash_Length')));						# Store the extracted ID if the hash is correct
	return $val													
}

#===================================
sub _check_hashed_identifier {															# Check if a hashed SID / UID is correct
#===================================								# Param 1 = 'UID'/'SID'/'_sh', # Param 2 = $id to check
	my $self = shift;

	my $secret = $self->_get_secret_key(shift);
	my $string = shift;
	return (substr($string,-$self->config('Hash_Length')) eq 
			$self->_generate_hash($secret,substr($string,0,-$self->config('Hash_Length'))));
}

#===================================
sub _get_hashed_secure_ID {															# Generates, stores and returns a secure hashed id based on the current SID
#===================================
	my $self = shift;
	return unless $self->request_logged_in;
	$self->_value('_sh' =>																	# Generates hash unless already generated
			$self->_generate_hash(
					$self->_get_secret_key('_sh')
					,$self->_value('SID')))
		unless $self->_value('_sh');
	return $self->_value('_sh');
}	

#===================================
sub _get_hashed_ID {																		# Generates, stores and returns a hashed UID  or SID
#===================================								# which consists of original ID with with hash appended
	my $self = shift;
	my $id = shift 
		|| warnings::warn('No ID requested - which one do you want?');

	my $string = $self->_value($id);

	$self->_value($id.'_hash' =>
		 	$string.$self->_generate_hash(
				$self->_get_secret_key($id)
				,$string))
		unless $self->_value($id.'_hash');
	return $self->_value($id.'_hash');
}	

#===================================
sub _get_secret_key {																			# Returns the key which pertains to UID, SID or _sh
#===================================
	my $self = shift;
	my $id = shift || warnings::warn('No ID requested - which one do you want?');
	if ($id eq 'SID') {
		return $self->config('Secret_Session_Key')									# For SIDs, secret key includes User Agent and hostname
				 .($self->request->hostname||'')									
				 .($self->request->header_in('User-Agent')||'');
	} elsif ($id eq 'UID') {
		return $self->config('Secret_User_Key');
	} else {
		return $self->config('Secret_Secure_Key');
	}
}



#===================================
sub _value {																						# Sets and retrieves values in this object
#===================================
	my $self = shift;
	my $param = '_'.shift;
	my $value = shift;
	$self->{$param} = $value if defined($value);
	return $self->{$param} if exists ($self->{$param});
	return undef;
}


#===================================
sub cookies_enabled {																		# Sets flag which reports whether a cookie has been received (thus enabled)
#===================================
	my $self = shift;
	my $val = shift;
	if (defined $val) {
		$self->{cookies_enabled} = $val;
	}
	return $self->{cookies_enabled};
}

#===================================
sub bake_cookies {																						# Add relevant cookies to headers out
#===================================
	my $self = shift;
	my $remember_me = $self->remember_me();												# Should the user's computer remember him or just use session cookies?
	my $cookies_to_bake = $self->_cookies_to_bake;										# Which cookies to send?
	

	DEBUG > 0 && print STDERR "\n*** ARM : 61 cookies_to_bake = $cookies_to_bake";

	 if ($cookies_to_bake & COOKIES) {															# Should we send standard cookies?
		Apache::Cookie->new($self->request,
			-name		=>	'UID',
			-value		=>	$self->_get_hashed_ID('UID'),
			-expires		=>	($remember_me ? $self->config('Cookie_Expiry') : ''),		# Remember user after this session?
			-domain		=>	$self->config('Cookie_Domain'),
			-path			=>	'/',
			-secure		=>	0
		)->bake;
		Apache::Cookie->new($self->request,
			-name		=>	'SID',
			-value		=>	$self->_get_hashed_ID('SID'),
			-domain		=>	$self->config('Cookie_Domain'),
			-path			=>	'/',
			-secure		=>	0
		)->bake;
	}

	 if ($cookies_to_bake & SECURE_COOKIES) {											# Should we send a cookie to show logged in for this session
		Apache::Cookie->new($self->request,
			-name		=>	'_sh',
			-value		=>	$self->_get_hashed_secure_ID,
			-domain		=>	$self->config('Cookie_Domain'),
			-path			=>	'/',
			-secure		=>	1																				# Only served in HTTPS
		)->bake;
	}
}

#===================================
sub _test_session_manager	{																					# Tries out Apache::Session parameters to confirm that they work
#===================================
	my $self = shift;
	my $mngr = $self->config('Session_Mngr');
	DEBUG > 9 && print STDERR "\n*** ARM : 62 Testing Apache Session settings\n"
		.Dumper($mngr);
	eval {																												# Store a hash in the session store, then delete it	
		tie my %hash, 'Apache::Session::Flex', undef , $mngr;
		tied(%hash)->delete;
	};
	if ($@)	{
		warnings::warn("Problem with Apache::Session manager parameters : ".$@);
		return 0;
	}
	return 1;
}

#===================================
sub _timestamp_session {																						# Stores a timestamp in the session
#===================================
	my $self = shift;
	$self->session->{'last_accessed'}	= time();
	return;
}

#===================================
sub remember_me {																								# Store long term cookies on this computer?
#===================================
	my $self = shift;
	my $val = shift;
	return $self->_value('remember_me' 	=> $val);
}


#===================================
sub _generate_random_key {																					# function call which generates a random string
#===================================
	my $length = shift||16;
	my $newstring = '';
	for (my $x=0;$x<$length;$x++) {
		$newstring.=substr(SRCSTRING,int(rand(61)),1);
	}
	return $newstring;
}

#===================================
sub _generate_hash {																							# Uses a secret key to generate a 16 character long hex MD5 hash of a string
#===================================
	my $self = shift;
	my $secret = shift || "";
	my $string = shift || "";
    DEBUG > 8 && print STDERR "\n*** ARM 62b : Generating hash : \nSecret : $secret \nString : $string \nHash_Length : ".$self->config('Hash_Length');
	return substr(md5_hex($secret,md5_hex($secret,$string)),0,$self->config('Hash_Length'));
}


#===================================
sub session {																										# Returns the stored session object
#===================================
	my $self = shift;
	return $self->{_session};
}

#===================================
sub get_sh {																										# Returns the stored session object
#===================================
	my $self = shift;
	return $self->_get_hashed_secure_ID;
}

#===================================
sub getSID {																										# Returns the stored session object
#===================================
	my $self = shift;
	return $self->_get_hashed_ID('SID')
}

#===================================
sub getUID {																										# Returns the stored session object
#===================================
	my $self = shift;
	return $self->_get_hashed_ID('UID');
}


#===================================
sub attach_object {																								# Attach object  - public method
#===================================
	my $self = shift;
	my $ok = 1;
	while (@_) {
		my $key = shift;
		if (ref $key eq 'HASH') {
			$ok &= $self->attach_object (%{$key});
		} else {
			my $value = shift;
			DEBUG > 8 && print STDERR "\n*** ARM : 63 Attaching object to method $key :\n"
				.Dumper($value);
			$ok &&= $self->_attach_object($key,$value)
		}
	}
	return $ok 
}

#===================================
sub _attach_object {																	# Stores an object in a hash ref in object data, and create a method with which to access it
#===================================							# private method
	my $self = shift;
	my $key = shift;
	unless ($key) {
		warnings:warn(ref($self),"No parameters passed to ->attach") ;
		return ;
	}
	my $object = shift;
	unless ($object) {
		warnings::warnif(ref($self),"No object passed to ->attach");
		return ;
	}
	eval "\$self->$key";
	DEBUG > 8 && print STDERR "\n*** ARM : 63a Method $key is already defined" unless $@;
    if ($@) {
		eval "sub $key { my \$self = shift; return \$self->{Attached_Objects}->{$key}}";				# Creates the method to access the object
	}
	$self->{Attached_Objects}->{$key} = $object;																# Stores the object
	return 1 unless $@;
	warnings::warn($@);
	return;
}


#===================================
sub config {																				# Retrieve config options  - public method
#===================================
	my $self = shift;
	my $key = shift || '';
	return undef unless exists $Config{$key};
	return $Config{$key}
}


#===================================
sub set_config {																			# Set config options  - public method
#===================================
	my $self = shift;
	my $ok = 1;
	while (@_) {
		my $key = shift;
		if (ref $key eq 'HASH') {
			$ok &= $self->set_config (%{$key});
		} else {
			my $value = shift;
			DEBUG > 8 && print STDERR "\n*** Setting config option $key to value :".(ref($value) ? "\n".Dumper($value) : $value);
			$ok &&= $self->_set_config($key,$value)
		}
	}
	DEBUG > 9 && print STDERR "\n*** ARM : 64 New config options : ".Dumper(\%Config);
	return $ok 
}

#===================================
sub _set_config {																			# Set config options - private method
#===================================
	my $self = shift;
	my $key = shift || '';
	unless (exists $Config{$key}) {													# Can only set predefined keys
		warnings::warn("$key is not a known Session Manager config options");
		return;
	}
	my $value = shift;
	$Config{$key} = $value;
	if ($value && $key eq 'Session_Mngr') {
		return $self->_test_session_manager();
	}
	return 1
}

1;

__END__



=head1 NAME

Apache::Session::Manager - Perl wrapper around Apache::Session, to provide short term session management and long term user
tracking, by cookie or URL. 

=head1 SYNOPSIS

Apache::Session::Manager doesn't provide the SQL to interact with your database.  You should subclass it 
with your own module (YourModule), and override the methods to do the database stuff (details and example included below).

	$mgr = Apache::Session::Manager::YourModule->new($r);

	$mgr = Apache::Session::Manager::YourModule->new($r,
            'cache'	=>    Cache::FileCache->new({CACHE_OPTIONS}),
            'page'	=>    Template-new(Template_Options)
	);

	$mgr->init();

	$mgr->login($username,$password);

	$mgr->logout();

	$mgr->create_new_account(
		$UID,
		$username,
		$password 
		[,$other_variables,...]
	);

	$mgr->remove_cookies;

	$mgr->bake_cookies;

	$string = $mgr->getSID();
	$string = $mgr->getUID();
	$string = $mgr->get_sh();

	$bool = $mgr->request_logged_in();
	$bool = $mgr->session_logged_in();

	$string = $mgr->is_registered( )

	$bool = $mgr->cookies_enabled();

	$mgr->remember_me(1);
	$bool = $mgr->remember_me();

	$mgr->session->{key} = $var;

	$apr = $mgr->request

	$mgr->attach_object('useful_object' => $useful_object);
	$mgr->useful_object->method();
	$value = $mgr->useful_object->{key};

	$mgr->set_config(
		Session_Expiry	=> 60*15,
		Secret_User_Key	=> 'abcdegh'
	);

=head1 ABSTRACT

Apache::Session::Manager provides a wrapper around Apache::Session which adds the following :

=over 4

=item * Short term session tracking using cookies or URLs (query string / POST data rather than URL munging)

=item * Long term user tracking with cookies and query string

=item * User recognition through query string

=item * Login, logout, create new account, remove cookies - all operating with your favourite database and schema!

=back

It needs to be subclassed by your own module, which provides the methods to interact 
with your database - ie you can integrate this module into you own database schema.

=head1 DESCRIPTION

Apache::Session::Manager is not a "drop in" module - it requires a bit of work on your part to make it work - but once that work
is done, it makes a lot of user and session management easy.  Any website that wants to have any sort of long term relationship
with a user needs to be able to track a user through a session, allow the user to register, and issue them with a password challenge
before allowing them to view restricted pages... which is exactly what this module does.

All you need to provide is 6 subroutines which speak to your database to perform a few simple functions (looking up a username etc).

This section gives an overview of how Apache::Session::Manager works.  See L</"INTEGRATING Apache::Session::Manager WITH YOUR WEBSITE">, 
L</"CONFIGURATION OPTIONS"> and L</"METHODS"> below for details.  Also, see L</"WHAT TO DO WHEN COOKIES ARE DISABLED?">

=head2 As a PerlAccessHandler

When Apache::Session::Manager is used to intercept requests as a PerlAccessHandler, it:

	* checks to see whether the user has a current (and unexpired) session,
	* if not, does he have a user cookie from a previous session
	* if not, create a new user ID (UID) and session (SID) for him

	if he does have a current session, 
	* is that session logged in, and if so 
	* has the user passed back the secure cookie (_sh)
	* which means that he has adequately identified himself as logged in 
	  for this request 

=head2 Working with PerlHandlers

Apache::Session::Manager also provides functionality to PerlHandlers - it automates login, logout
and the removal of cookies.  

So your module might take the username and password from the user, make sure that they are in the right 
form, or long enough or whatever else you want to check, pass them through to Session Manager, which tries to
log the user in and either passes back success or an error message.

It's now 2am - I don't know if this makes enough sense (any sense?). Let me know if it doesn't, and I'll try to answer 
your questions more intelligently.


=head1 METHODS


=over 4

=item $mgr = Apache::Session::Manager->new($r,[$key=>$ref,$key=>$ref...])

Creates a new Apache::Session::Manager object.  Should only called from your module which subclasses Apache::Session::Manager.  From then on 
you should call the new method from your module (see L</"INTEGRATING Apache::Session::Manager WITH YOUR WEBSITE"> for details).

Useful feature... rather than passing around an Apache::Request object, and a Template object and a Cache::Cache object,
you can put them all inside your Apache::Session::Manager object with (eg):

	$mgr = Apache::Session::Manager::YourModule->new($r,
            'cache'	=>    Cache::FileCache->new({CACHE_OPTIONS}),
            'page'	=>    Template-new(Template_Options)
	);

See attach_object() for details.


=item $mgr->init( )

Initialises a newly created Apache::Session::Manager object.  This tries to find a session from the user's cookies and
query string, and tries to find information in the database., so only call this after you have blessed this object into your
own module.  See L</"INTEGRATING Apache::Session::Manager WITH YOUR WEBSITE"> for details.

=item $mgr->login($username , $password)

Given a username and password, this method tries to look the user up in the database and, assuming the password
is correct, log them in.

	($UID,$error) = $mgr->login($username,$password)

If it is succesful, it returns the user's UID, otherwise an error message with a value of:

	username    : if the username doesn't exist
	password    : if the username exists, but the password is wrong

Login tries to be practical about what to do with an existing session when a user logs in.  There are a few scenarios here:

 * this is the first time a user (and his computer) has been on this site
 * a new user is using this site, but the computer has UID cookie present
   from a previous user (whose session expired ages ago)
 * a call centre agent logs into one account after another

The question here, is what to do with things stored in a user's session.  If the current user adds something to their basket
and then logs in, what do you do with their basket.  Do the basket contents belong to the current user or
to the previous user?

In the first scenario, it's easy - there IS no other user.

With the last two scenarios, the distinguishing factor is, is the previous user's session already logged in? 
In the second scenario, the answer is no, because the session has expired, so the basket belongs to the new user. In
the third scenario, the session is still active, so there must have been a quick handover between the two (as you
would see with call centre agents), so the current contents belong to the original user, and not the new user.



=item $mgr->logout( )

This expires a user's session, and issues a new SID.  However, the UID cookie is still there
so your site can still say "Welcome back, gorgeous".  If you want to wipe their UID cookie, see remove_cookes() below.

=item $mgr->create_new_account($username, $password[,$other_vars,...])

To create a new account for the user, call this account as above, appending any other variables
you would like to store in the database at this time. (You'll be writing the SQL that performs this action,
so you can put in there what you like eg nickname, mailing opt-out, etc)

Call it as : 

	($UID,$error) = create_new_account($username, $password[,$other_vars,...])

If an account is created succesfully, a $UID is returned.

Otherwise, $error can have any value that you set for it - eg 'username' if that username is already used etc. (see 
L</"INTEGRATING Apache::Session::Manager WITH YOUR WEBSITE"> for implementation)

=item $mgr->remove_cookies( )

This means, don't only log me out, remove all traces of this site from my computer! (For instance, a user may be
browsing on a public computer.  This logs the user out and sets remember_me to false.  As soon as you call $msg->bake_cookies
and send the headers, the deed is done!

The user's session is expired, and a new UID and SID are issued.

=item $mgr->bake_cookies( )

This should be called just before $r->send_http_header is called.  This ensures
that any cookies that need to be sent to the client are sent, but not before you're sure that
no other process is going to fail and spew Internal Server Error pages to your user.


=item $mgr->getSID( )

Returns the current hashed session ID, which is in a form that can be passed to users - ie the same thing that gets 
passed in the cookie.

=item $mgr->getUID( )

Returns the current hashed user ID, which is in a form that can be passed to users - ie the same thing that gets 
passed in the cookie.

=item $mgr->get_sh( )

Returns the current hashed secure session ID, which is in a form that can be passed to users - ie the same thing that gets 
passed in the cookie. If $mgr->request_logged_in() is false, then this returns C<undef> instead.



=item $mgr->request_logged_in( )

A flag indicating whether the user is logged on for this request or not .  A true value
indicates that they have returned the secure hash either 
via a secure cookie or in POST data from a secure form (the implementation of which is up to you - 
see L</"WHAT TO DO WHEN COOKIES ARE DISABLED?">


=item $mgr->session_logged_in( )

A flag indicating whether the user has logged in during this session or not.  Can be allowed
to access pages which are not quite as senstive but do require some identification.

=item $mgr->is_registered( )

If the current UID has an associated username, returns true (ie this account is registered).  In fact, 
it returns the user name.

=item $mgr->cookies_enabled( )

If the client passed either a session or a user cookie through, then this flag is set to true.  If it is false,
then this may be the first request, or cookies may be disabled.

Either way, it means we need to put the SID into any links that he may follow from this page.

If cookies are enabled, but this was the first request, then on the next request, this flag will be set to true.

=item $mgr->remember_me( [$flag] )

If the user wants to be recognised when he returns to the site, we can put a long term user cookie on his computer.
However, if he doesn't want to be recognised then we can set the expiry time for the user cookie to immediate. So 
as soon as the user closes his browser, the cookie goes up in smoke.

Clearly this will only have an effect when a cookie gets dropped, so login is a good time to do it.

It is true by default, so to set it to false, just use :

	$mgr->remember_me(0);

If called without an argument, it returns its current value.

=item $mgr->session

This returns the Apache::Session object.  You can use it as a normal hash eg:

	$mgr->session->{$key} = $value 
		if exists $mgr->session->{$key}

=item $mgr->request

Returns an Apache::Request object for this request.

=item $mgr->attach_object($method_name => $ref[,...])

Useful feature... rather than passing around an Apache::Request object, and a Template object and a Cache::Cache object,
you can put them all inside your Apache::Session::Manager object, either at object creation time (see new() for details)
or later with (eg):

	$mgr->attach_object(
	  'cache' => Cache::FileCache->new()
	) || die "Couldn't attach object cache";

Later on, you can access the cache object like a method : 

	$mgr->cache->get(...);
	$mgr->cache->set(...);

What happens internally is this.  The object ($ref) is stored in a hash inside the $mgr object, 
and a new method is created, which returns that $ref.




=item Apache::Session::Manager->set_config($option=>$value[,...])

See below for L</"CONFIGURATION OPTIONS">

This method can be called either with a list of key/value pairs, or with a hash ref. Returns true if succesful, and false if any one of 
the options has failed.

B<PLEASE NOTE : > It makes a big difference when you call set_config for some options. See the notes on Session_Mngr 
and Secret_Session_Key in L</"CONFIGURATION OPTIONS"> below.

=back



Consider this example : a user doesn't have cookies enabled, so we're using query string SID tracking.
They forward a link to the person sitting next to them, who immediately looks at it.

Now, the SID is in the query string, and the session is still active, so the friend picks up the same session as the original user!  
Bugger! Hopefully, User-Agent and hostname will be reported differently and so the new user will be recognised as a different person, 
but this could happen!

Fortunately, the user won't be able to transfer a logged in session to a friend. Ever. Unless they try really hard.



=head1 INTEGRATING Apache::Session::Manager WITH YOUR WEBSITE

To use Apache::Session::Manager, you need to subclass it so that your module can provide the link to your database
that this module lacks.  This takes a little time, but is not difficult. 

=head3 There are 6 steps:


=over 4

=item 1 Decide what you are going to use for your Apache::Session store

=item 2 Create a database

=item 3 Subclass Apache::Session::Manager (Apache::Session::Manager::YourModule)

=item 4 Write a handler (Apache::YourHandler) to interface with YourModule

=item 5 Set your handler as a PerlAccessHandler

=item 6 Add module initialisation to the right phase in Apache startup

=back

=head3 STEP 1 : WHAT TO USE FOR Apache::Session STORE

Please read the Apache::Session and Apache::Session::Flex documentation. Decide what you want to use, create 
the relevant database, configure it anyway you please.  Anything goes here!

=head3 STEP 2 : CREATE A DATABASE

(This is separate from the 'sessions' table you may need for Apache::Sessions - read that section separately)

Apache::Session::Manager requires one table to store user information. You write the SQL to access this table
so you can call it anything you like, but as example : 

	CREATE TABLE user (
	  creationdate datetime NOT NULL,
	  UID varchar(32) NOT NULL,
	  SID varchar(32) NOT NULL,
	  username varchar(100) NOT NULL,
	  passwd varchar(20) NOT NULL,
	# and any other columns you want (eg name, nickname, opt-out etc)
	  nickname varchar(100) NOT NULL, 
	  PRIMARY KEY  (UID),
	  KEY username (username),
	  KEY nickname (nickname)
	)

The UID length can be configured (see L</"CONFIGURATION OPTIONS"> below).  SID length can be set with
Apache::Session::Flex options.

=head3 STEP 3 : SUBCLASSING Apache::Session::Manager - YourModule

You need to a write a module as a subclass to Apache::Session::Manager to provide the methods used to access the database. As long
as these methods fulfill the requirements of Session Manager, you can add other bits that do what you need.  For instance, when 
creating a new account, all that is required is Username and Password. But you may want to store Name, Opt-Out, etc at the same time.

PLEASE NOTE : Code below is an example only. It has no error checking etc - you need to figure that out yourself.

Create your module along these lines :

	==================================
	package Apache::Session::Manager::YourModule;
	use warnings;
	use strict;
	
	use DBI;

	sub new {
		my $proto = shift;                      
		my $class = ref ($proto) || $proto;
	
		# Create a database handle which will be used for managing users (see below)
		my $dbh = connect->(DBI:...... etc);

		# Get a new Apache::SesionManager object
		my $self = $class->SUPER::new(@_)      
			|| warnings::warn($Apache::Session::Manager::errstr);
	
		# Then make it an Apache::Session::Manager::YourModule object
		bless($self,$class);                   

		# Attache the database handle for easy access later
		$self->attach_object(dbh => $dbh);

		# Initialise the object for this request
		$self->init();

		return $self;
	}

	# SID = Session ID
	# UID = User ID

	# These subroutines can use the database handle attached to the 
	# Apache::Session::Manager::YourModule object to prepare statements
	# and execute the SQL

	sub update_users_SID {
	#===================================
		# Params : $UID, $SID
		# Action : Try to set the SID for this UID to SID (blank for no session)
		# Returns : undef if couldn't find UID
		# example code :

		my $mgr = shift;
		my $UID = shift;
		my $SID = shift;

		my $sth = $mgr->dbh->prepare_cached(<<SQL);
			UPDATE database.user
			SET SID = ?
			WHERE UID  = ?
		SQL

		$sth->execute($SID,$UID);

		return $sth->rows;
	}


	sub get_users_SID {
	#===================================
		# Params : $UID
		# Action : Try to get the SID for this UID 
		# Returns : undef if couldn't find UID, blank if UID found, but no session
		#           assigned that UID
		# example SQL : 

		SELECT SID
		FROM database.user
		WHERE UID  = ?

		return undef unless row found
		otherwise, return SID
	}


	sub insert_new_UID {
	#===================================
		# Params : $UID, $SID
		# Action : Try to insert new UID and set the SID for this UID to $SID
		# Returns : undef if couldn't insert UID
		# example SQL :

		INSERT INTO database.user (UID,SID,creationdate)
		VALUES (?,?,now())
	}

	sub get_login_UID {
	#===================================
		# Params : $username, $password
		# Action : Try to find a matching username and password
		# Returns : ($UID,$error). $UID is undef if matching pair not found
		#           $error is one of 'username' or 'password' depending 
		#           which was at fault
		# example SQL :

		SELECT 	UID
		        ,if(password(?) = passwd,'1','0') as password_ok
		FROM database.user u
		WHERE u.username = ?

		return (undef,'username') unless a result found
		return (undef,'password') unless password_ok is true;
		otherwise return UID

	}

	sub set_username_and_password {
	#===================================
		# Params : $UID,$username, $password, anything else
		# Action : Update username and password (and anything else) for $UID
		# Returns : true for success, false for failure
		# example SQL :

		UPDATE bush.user 
		SET username = ?
		    ,passwd = password(?)
		    ,anything_else_you_want_to_pass = ?
		WHERE UID = ?
	}

	sub check_username_available {
	#===================================
		# Params : $UID, $username, $anything else
		# Action : Check if this username (and anything else) already exists, also if current UID is already taken
		# Returns : ($UID,$error). $UID is undef if there is an error
		#            $error is 'uidtaken' if the current user's UID already has a username against it
		#            otherwise can pass back any other errors
		# example SQL : 

		# Use get_login_UID above to check if the username is taken

		return (undef,'username') if UID found

		#Then check for any other unique fields that you may 
		#have passed through (eg nickname)
	
		SELECT 	UID
		FROM database.user u
		WHERE 	u.nickname= ?
	
		return (undef,'nickname') if UID found

		# Then, can we create an account using the current UID
		# or does that UID belong to a different account

		SELECT 	username
		FROM database.user u
		WHERE u.UID=?

		return (undef,'uidtaken') if username is not blank

		#Otherwise use this UID!
		return $UID;
	}


	sub load_session {
	#===================================
		# Params : $UID
		# Action : Loads a session including (mandatory) username
		# Returns : username if exists, otherwise blank
		# Anything that needs to be loaded and added to session can go in your overriding method
		# example SQL :

		SELECT username,name
		FROM database.user u
		WHERE u.UID = ?

		$mgr->session->{name} = $result->{name};
		return $result->{username}
		
	}



	1;
	__END__
	==================================


=head3 STEP 4 : WRITING Apache::YourHandler TO INTERFACE WITH YourModule

This is probably the trickiest bit to explain, because it relies on how you have set things up.  Here goes...

This handler will receive requests for pages and may have to decide things like : 

=over 4

=item 1 Should it handle this request at all?

=item 2 Should it handle this request under SSL only?

=item 3 Does the user need to be logged in to see this page, and are they logged in?

=item 4 Assuming all of the above is OK, what module should handle this page?

=back

I provide this as an example of how you might use 
Apache::Session::Manager. This 
code relies on a hash containing a list of URLs which will be served by mod_perl.

The hash is of the form:

	%URLs = (
	    '/home' => {
	        handler      => 'Apache::Home',
	        secure       => 0,
	        must_login   => 0});


	==================================
	package Apache::YourHandler;

	use strict;
	use warnings;
	use Apache::Session::YourModule();
	use Apache::Constants qw(REDIRECT DECLINED OK);
	use Apache::URI();
	
	%URLs = (...URL DETAILS...);

	sub handler {
	#============
    	  my $r = shift;

	  # If mod_perl is handling http://your.domain.com/, then Apache's mod_dir.c
	  # sets up an internal redirect, which means this phase gets called twice
	  # and issues new UID's & SID's each time
	  return DECLINED unless $r->is_initial_req(); 

          # If URL not handled by mod_perl - pass back to Apache
	  return DECLINED unless exists $URLs{$r->uri);
	  my $url = $URLs{$r->uri);

	  # Env variable set in the virtual server to indicate that
	  # this request has been served securely

	  my $SSL = $ENV{SSL} ||0;                                                            

	  # If we're not working through HTTPS and the page requires SSL, 
	  # then redirect to HTTPS
    	  return redirect_secure($r) if  !$SSL && $url->{secure};                        

	  my $mgr =  Apache::Session::YourModule->new($r);

	  # This way, you can get hold of this object for handlers called later on
    	  $r->pnotes('manager'=>$mgr);

    	  # If needs to be logged in to view this page, and isn't logged in...
    	  if ($url->{must_login} && ! $mgr->request_logged_in) {
            # Get a secure page for login
            return redirect_secure($r) if  !$SSL;
            $r->push_handlers(PerlHandler => 'Apache::YourLogin');
	  } else {
	    $r->push_handlers(PerlHandler => $url->{handler});
	  }
	  return OK;
	}

	sub redirect_secure {
	#====================
	  my $r = shift;
	  my $uri = Apache::URI->parse($r);
	  $uri->scheme('https');
	  $uri->port('443');
	  $r->header_out (Location=>$uri->unparse);
	  return REDIRECT;
	}

	1
	__END__

	==================================





=head3 STEP 5 : SET YourHandler AS A PerlAccessHandler

In httpd.conf : 

	PerlAccessHandler Apache::Session::Manager::YourHandler

=head3 STEP 6 : INITIALISING YourModule DURING STARTUP

In your startup.pl file (you do have one of those, don't you?)

	==================================
  	use Apache::Session::Manager::YourModule

	# NB READ THE NOTE ABOUT THE Secre_Session_Key CONFIG OPTION BELOW

	Apache::Session::Manager::YourModule->set_config (
		Cookie_Domain          => '.youdomain.com',			
		Secret_User_Key        => 'your secret phrase'
	);

	# NB READ THE NOTE ABOUT THE Session_Mngr CONFIG OPTION BELOW

	Apache::Session::Manager::YourModule->set_config (
		Session_Mngr	=> { ...Apache::Session::Flex config options ...}
	) || die "Couldn't connect to Apache::Session store";
	==================================


=head3 INTEGRATION COMPLETE! 

Well done, buy yourself a beer.  Now buy youself another beer...

=head1 WHAT TO DO WHEN COOKIES ARE DISABLED?

So what do you do if a user has cookies disabled? There are two situations to cater for : 
(1) maintaining an ordinary session and (2) maintaining a logged in state.

The solution which I'm suggesting (and it may not be the right one) is to use the query string or post data to pass information from 
page to page.  So, for (1) above, this means that every link also needs to have an SID attached, so:

	<a href="home?SID=123456">

For (2), it's slightly more complicted. To make sure that our session can't be hijacked, we need an ID that is only passed back 
to the server across SSL.  With cookies it's easy - just set the secure flag on your cookie.

Without cookies, it means that you need to pass both 'SID' and '_sh' across every link, where _sh is the parameter that holds the
secure hashed ID.  

So do something like :
	
	unless ($mgr->cookies_enabled) {
	    $SID = $mgr->getSID;
	    $_sh = $mgr->get_sh;
	}

And use those values to construct the correct URLs or hidden fields.

B<PLEASE NOTE! :> It is important that _sh is never transmitted in clear text, otherwise it becomes worthless. Instead, from the time
a user logs in, we include _sh as a field in a query string or as a hidden field in a form for every destination that is also 
served through https.  If it is a link to an insecure page, then it shouldn't include _sh - they will just have to log in again
the next time they want to access something secure.

B<PLEASE NOTE!! :> The above is still insecure.  Really, the _sh should never appear in a query string - the next user can look back
in the history and take over that session. Which means that the only way to pass _sh is through POST data, which means that every 
secure page needs to be a form! (And of course, form data can be resubmitted by pressing refresh, as long as the user
hasn't shut down their browser). 

Or you could just say TOUGH!  If you want to log in, use cookies!  Depends how sensitive your data is, really.

I haven't implemented URL-munging. It's a solution fraught with complexity, and I just don't like the look of it. 
Also, it makes your URLs look REAL funny in a search engine. And I haven't seen anybody use it for ages.  But some people
may want it.  There's no accounting for taste.


=head1 CONFIGURATION OPTIONS

See method : set_config() above for details of how to set.

=over 4

=item 	Session_Mngr		(Default : Undefined)

Session_Mngr should be set to a hash containing configuration options for Apache::Session::Flex. (see the L<"Apache::Session::Flex"> 
documentation for details). When this option is set, Apache::Session::Manager attempts to create a new session and delete it to make 
sure it is working, so use 

	$mgr->set_config (
		Session_Mngr	=> {
			...Apache::Session::Flex options...
			}
	) || die "Couldn't connect to the Apache::Session store";

The Apache::Session error message will be printed to STDERR.

B<PLEASE NOTE> : If you use a database handle as a configuration option (eg Handler => $dbh), then only set this option
during PerlChildInit rather than during server initialisation.  Children cannot share a database 

=item 	Session_Expiry		(Default : 15 minutes)

This specifies (in seconds) how long a session should be considered alive while there is no activity from the user. 
Make it shorter if you're feeling security conscious.

=item	Cookie_Domain          (Default : blank)

The cookies will be returned by the client for the domain you specify, so if you only want it to be served to this machine,
then specify 'thismachine.yourdomain.com'.

If you'd like it be served to other machines in your collection (eg www2., mail. etc) then specify '.youdomain.com'

The default is blank, which means, only serve to this machine.

=item	Cookie_Expiry          (Default : 1 year)

How long before your user's user-cookie should expire?  Lets face it, if they haven't come back in one year, are the likely to? 
And do you want to clutter your database with aging unused accounts?

=item	UID_Length             (Default : 32)

The User ID, the string which identifies users between sessions, is generated with MD5 hashing so as to avoid being sequential. 
The longer this value, the less chance that it will already exist. (see Hash_Length)

=item 	UID_Tries              (Default : 20)

How many times should we try to insert a new UID before we give up?   If you get error 
messages about this failing, then increase this number.

=item	Hash_Length            (Default : 16)

Session IDs and User IDs are hashed to reduce the chances of anybody guessing a real UID.  This hash gets
passed back to the user along with the original ID, so the length of what they see in a URL is Hash_Length + UID_Length.

=item	Secret_User_Key        (Default : Undefined)

This string is hashed with the UID to produce a hash which is used to verify whether the UID is valid or not.  This value must be
set, otherwise the hash becomes too predictable.  And be aware, if you change this value, then your web site will no longer
recognise older users, until they log in again.

=item 	Secret_Session_Key     (Default : Randomly generated key)

This string is hashed with the SID, the hostname and the User Agent, to provide a hashed SID that (hopefully) will not be
valid for any other computer. Either set this to something yourself, or rely on the default randomly generated string.  

B<PLEASE NOTE>: If you do rely on the default, then you MUST load this module during server startup.  This way the random string gets
preset for all future children.  Otherwise, each child has a different string, and the user will have a new session started with
every request. 

Also, if you restart your server while a user is browsing, then their session will expire. This is not a problem
if you do things like saving shopping baskets when you expire sessions. In fact, it might even be considered a feature.

=item 	Secret_Secure_Key      (Default : Randomly generated key)

This string is hashed with the SID to produce a key which is stored in a secure cookie.  If a user doesn't return this cookie
then they are not logged in for that particular request.  See note for Secret_Session_Key above.

=back

=head1 INSTALLATION

The usual : 

   % perl Makefile.PL
   % make
   % make install

Or : 

   % perl -MCPAN -e shell
   cpan> install Apache::Session::Manager

Or even, just copy SessionManager.pm to a subdirectory (called Apache) of your other perl modules, 
but don't forget to install the L<"PREREQUISITES">.

=head1 PREREQUISITES


This module will probably work with older versions than I have specified below, but I haven't tried it.

=over 4

=item perl 5.8

=item mod_perl 1.27

=item Apache::Cookie 1.0

=item Apache::Request 1.0

=item Apache::Session 1.54

=item Digest::MD5 2.20

=back




=head1 SEE ALSO

Please read the Apache::Session and Apache::Session::Flex documentation to find out how to set up the Apache::Session::Flex correctly.

Also, read Apache::Cookie and CGI::Cookie.

=head1 STATUS

This module is currently in beta.  I have tested it extensively, but it is still in flux.  The major methods will 
probably remain the same though. It is in active development.

Please use, rip apart, debug, swear at and send me any suggestions, bugs or bug-fixes!


=head1 AUTHOR

Clinton Gormley <develop@drtech.co.uk>

=head1 COPYRIGHT AND LICENSE

Copyright 2002 by Clinton Gormley

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=head1 TODO

=over 4

=item Test suite

=item Sticky sessions with mod_backhand

=item You tell me!

=back


=head1 CHANGES

=head2 Version 0.03

* Method logged_in became request_logged_in
* Added method session_logged_in
* Added call to load_session() - can be overriden by the user to restore a saved session.  Not required.
* Fixed Cookie_Expiry bug ('1y' should have been '+1y')
* Added is_registered method
=cut
