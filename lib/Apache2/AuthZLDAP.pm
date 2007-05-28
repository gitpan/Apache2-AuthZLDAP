package Apache2::AuthZLDAP;

use warnings;
use strict;
use mod_perl2;
BEGIN {
		require Apache2::Const;
		require Apache2::Access;
		require Apache2::SubRequest;
		require Apache2::RequestRec;
		require Apache2::RequestUtil;
		require Apache2::Response;
		require APR::Table;
		Apache2::Const->import(-compile => 'HTTP_UNAUTHORIZED','OK', 'HTTP_INTERNAL_SERVER_ERROR');
		require Apache2::Log;
		require Apache2::Directive;
		require Net::LDAP;
} 
=head1 NAME

Apache2::AuthZLDAP - Authorization module based on LDAP filters or LDAP groups

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

This module is an authorization handler for Apache 2. Its authorization method relies on openLDAP filters.

=head1 CONFIGURATION

This module can work with all authentification module that provides a valid REMOTE_USER env var. For example :

=over

=item *
basic auth

=item *
CAS authentication (mod_cas)

=back 

Example with CAS authentication :

    <VirtualHost 192.168.0.1:80>
    ## this vars can be initialized out of directory 
    PerlSetVar LDAPhost            myldaphost
    PerlSetVar LDAPbaseDN          ou=groups,dc=organization,dc=domain

 
    <Directory "/var/www/somewhere">
    AuthName CAS
    AuthType CAS
    ## define a filter. [uid] will be replaced by user value on runtime 
    PerlSetVar LDAPfilter        &(member=uid=[uid],ou=people,dc=organization,dc=domain)(cn=admins)
    ## charging of the module for authZ
    PerlAuthzHandler Apache2::AuthZLDAP
    require valid-user
    </Directory>

    </VirtualHost>

Other configuration directives (optional) :

=over

=item *
PerlSetVar LDAPTLS (yes|no) ## is the session TLS ? default no

=item *
PerlSetVar LDAPCAfile <path> ## see start_tls cafile option in Net::LDAP 

=item *
PerlSetVar TLSverify (none|optional|require) ## see start_tls verify option in Net::LDAP 

=item *
PerlSetVar LDAPuser myuser # if user/paswword required to bind

=item *
PerlSetVar LDAPpassword mypasswd # id.

=item *
PerlSetVar LDAPscope (base|one|sub) # default sub

=back 

=cut

sub handler{
    my $r= shift;
    return Apache2::Const::OK unless $r->is_initial_req;

    ## Location Variables to connect to the good server
    my $LDAPHost = lc($r->dir_config('LDAPhost')) || "localhost";
    my $LDAPPort = $r->dir_config('LDAPport') || "";
    my $LDAPTLS =  lc($r->dir_config('LDAPTLS')) || "no";
    my $CAfile =  lc($r->dir_config('TLSCAfile')) || "";
    my $TLSverify = lc($r->dir_config('TLSverify')) || "optional";
    my $ciphers = $r->dir_config('TLSciphers') || 'ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP';
    if($LDAPTLS ne "yes" && $LDAPTLS ne "no"){
	$LDAPTLS="no";
    }
    ## bind
    my $LDAPUser = $r->dir_config('LDAPuser')|| ""; 
    my $LDAPPassword = $r->dir_config('LDAPpassword')|| "";
    my $customFile = $r->dir_config('ResponseFile') || "";

    ## baseDN and Filters
    my $LDAPbaseDN = $r->dir_config('LDAPbaseDN'); ## list for which the mail will be checked
    my $LDAPscope =  $r->dir_config('LDAPscope') || "sub";
    my $LDAPfilter = $r->dir_config('LDAPfilter')|| "";
    
    
   
    my $auth_type = lc($r->auth_type) ||"";
    my $location = $r->location;
    ## did user authentified ?
    ## retrieval of user id

    my $user = $r->user || "";
    if ($user eq ""){
	$r->log_error("Apache2::AuthZLDAP : $location, user didn't authentify uid empty");
	return Apache2::Const::HTTP_UNAUTHORIZED; 
    }else{
	$LDAPfilter =~ s/\[uid\]/$user/;
    }

    
    ## port initialisation
    if($LDAPPort eq ""){
	if($LDAPTLS eq 'no'){
	    $LDAPPort = 389;
	}else{
	    $LDAPPort = 636;
	}
    }
    if($LDAPTLS eq 'no'){
	if($LDAPHost =~ /^ldap(|s):\/\//){
	    $LDAPHost =~ s/^([^:]*:)/ldap:/;
	}else{
	    $LDAPHost = "ldap://".$LDAPHost;
	}
    }else{
	if($LDAPHost =~ /^ldap(|s):\/\//){
	    $LDAPHost =~ s/^([^:]*:)/ldaps:/;
	}else{
	    $LDAPHost = "ldaps://".$LDAPHost;
	}
    }

    my $session;
    my $mesg;
    my $connectionstring="$LDAPHost:$LDAPPort";

    if ($LDAPTLS eq "yes"){
	if ($CAfile ne ""){
	    unless ($session = Net::LDAP->new($connectionstring,cafile=>$CAfile,verify=>$TLSverify,onerror=>sub{	$r->log_error("Apache2::AuthZLDAP : $location, $@ "); die;})){
		$r->log_error("Apache2::AuthZLDAP : $location, LDAP error cannot create TLS session on verify='$TLSverify' to $LDAPHost:$LDAPPort");
		return Apache2::Const::HTTP_UNAUTHORIZED;
	    }
	}else{
	    unless ($session = Net::LDAP->new($connectionstring,onerror=>sub{	$r->log_error("Apache2::AuthZLDAP : $location, $@ "); die})){
		$r->log_error("Apache2::AuthZLDAP : $location, LDAP error cannot create TLS session to $LDAPHost:$LDAPPort");
		return Apache2::Const::HTTP_UNAUTHORIZED;
	    }
	}
    }else{
	unless ($session = Net::LDAP->new("$LDAPHost:$LDAPPort",onerror=>sub{	$r->log_error("Apache2::AuthZLDAP : $location, $@ "); die})){
	    $r->log_error("Apache2::AuthZLDAP : $location, LDAP error cannot create session to $LDAPHost:$LDAPPort");
	    return Apache2::Const::HTTP_UNAUTHORIZED;
	}
    }
    
    
    
    ## user password bind if configured else anonymous
    if($LDAPUser ne "" && $LDAPPassword ne ""){
	$mesg = $session->bind($LDAPUser,password=>$LDAPPassword);
	if($mesg->code){
	    $r->log_error("Apache2::AuthZLDAP : $location, LDAP error cannot bind to $LDAPHost:$LDAPPort : ".$mesg->error);
	    return Apache2::Const::HTTP_UNAUTHORIZED; 
	}
    }else{
	my $mesg = $session->bind;
	if($mesg->code){
	    $r->log_error("Apache2::AuthZLDAP : $location, LDAP error cannot bind to $LDAPHost:$LDAPPort : ".$mesg->error);
	    return Apache2::Const::HTTP_UNAUTHORIZED; 
	}
    }

    
    ## search performing, if there is a result, OK
    $mesg = $session->search( # perform a search
			   base   => $LDAPbaseDN,
			   scope => $LDAPscope,
			   filter => $LDAPfilter,
			   );
        if ($mesg->count != 0){
	$r->log->notice("Apache2::AuthZLDAP : $user authorized to access $location");  
	$session->unbind;
	return Apache2::Const::OK;
    }else{
	$session->unbind;
	$r->log_error("Apache2::AuthZLDAP : $user not allowed to access $location");
	return Apache2::Const::HTTP_UNAUTHORIZED;
    }
    
    
    

}

=head1 AUTHOR

Dominique Launay, C<< <dominique.launay AT cru.fr> >>

=head1 BUGS

Please report any bugs or feature requests through the web interface at
L<https://sourcesup.cru.fr/tracker/?func=add&group_id=354&atid=1506>
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Apache2::AuthZLDAP


=over 4


=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2007 Dominique Launay, all rights reserved.

This program is released under the following license: GPL

=cut

1; # End of Apache2::AuthZLDAP
