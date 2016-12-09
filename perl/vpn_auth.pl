use strict;
use warnings;

use Cache::Memcached;
use Authen::OATH;
use Convert::Base32;
use Data::Dumper;

use lib '.';
use lib '/etc/freeradius/perl';
use MapGroup;

our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK, %RAD_CONFIG, %RAD_STATE);

our $force_mfa = 0;

use constant {
	RLM_MODULE_REJECT   => 0, # immediately reject the request
	RLM_MODULE_OK       => 2, # the module is OK, continue
	RLM_MODULE_HANDLED  => 3, # the module handled the request, so stop
	RLM_MODULE_INVALID  => 4, # the module considers the request invalid
	RLM_MODULE_USERLOCK => 5, # reject the request (user is locked out)
	RLM_MODULE_NOTFOUND => 6, # user not found
	RLM_MODULE_NOOP     => 7, # module succeeded without doing anything
	RLM_MODULE_UPDATED  => 8, # OK (pairs modified)
	RLM_MODULE_NUMCODES => 9, # How many return codes there are
};

# Same as src/include/radiusd.h
use constant {
	L_DBG   => 1,
	L_AUTH  => 2,
	L_INFO  => 3,
	L_ERR   => 4,
	L_PROXY => 5,
	L_ACCT  => 6,
};

sub authenticate {
	#&log_request_attributes;
	# this is challenge response. use cached session state if neccesary
	if (exists($RAD_STATE{'User-Name'})) {
		my @groups = MapGroup::map_group($RAD_STATE{'Filter-Id'});
		my $k = $RAD_STATE{'User-Name'} . ":" . $RAD_REQUEST{'Calling-Station-Id'};
		if (verify_totp($RAD_REQUEST{'User-Password'})) {
			set_usercache($k);
			$RAD_REPLY{'User-Name'} = $RAD_STATE{'User-Name'};
			$RAD_REPLY{'Filter-Id'} = \@groups;
			return RLM_MODULE_OK;
		} else {
			$RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
			$RAD_REPLY{'Reply-Message'} = "Incorrect OTP code. Try again";
			return RLM_MODULE_HANDLED;
		}
	}

	# normal username/password authentication

	# if no totp secret is set, fail or skip OTP challenge-response
	my @groups = MapGroup::map_group($RAD_CHECK{'Filter-Id'});

	my $need_mfa = 0;
	if ($force_mfa == 1 || MapGroup::is_priviledged(@groups) || exists($RAD_CHECK{'TOTP-Secret'}) ) {
		$need_mfa = 1;
	}

	if (not $need_mfa) {
		$RAD_REPLY{'User-Name'} = $RAD_REQUEST{'User-Name'};
		$RAD_REPLY{'Filter-Id'} = \@groups;
		return RLM_MODULE_OK;
	}

	if ($need_mfa && not exists($RAD_CHECK{'TOTP-Secret'})) {
		$RAD_REPLY{'Reply-Message'} = "Please configure 2FA in account settings";
		$RAD_REPLY{'User-Name'} = $RAD_REQUEST{'User-Name'};
		$RAD_REPLY{'Filter-Id'} = \@groups;
		return RLM_MODULE_REJECT;
	}

	# if login successfully recently, skip OTP challenge-response
	# currently, we can only exempt user by client IP
	my $k = $RAD_REQUEST{'User-Name'} . ":" . $RAD_REQUEST{'Calling-Station-Id'};
	if (check_usercache($k)) {
		&radiusd::radlog(L_DBG, "User-Name: $RAD_REQUEST{'User-Name'} skips OTP challenge");
		$RAD_REPLY{'User-Name'} = $RAD_REQUEST{'User-Name'};
		$RAD_REPLY{'Filter-Id'} = \@groups;
		return RLM_MODULE_OK;
	}

	# save session state and send OTP challenge
	$RAD_STATE{'User-Name'} = $RAD_REQUEST{'User-Name'};
	if (defined $RAD_CHECK{'Filter-Id'}) {
		$RAD_STATE{'Filter-Id'} = $RAD_CHECK{'Filter-Id'};
	}
	$RAD_STATE{'TOTP-Secret'} = $RAD_CHECK{'TOTP-Secret'};

	$RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
	$RAD_REPLY{'Reply-Message'} = "OTP Code";

	return RLM_MODULE_HANDLED;
}

sub post_auth {
	return RLM_MODULE_OK;
}

sub verify_totp {
	my $code = shift;
	my $oath = Authen::OATH->new();
	my $secret = $RAD_STATE{'TOTP-Secret'};
	$secret =~ s/{TOTP_TOKEN}//;
	for(my $i = 0; $i < 3; $i++) {
		my $totp = $oath->totp($secret, time() - 30 + $i*30);
		if ($code == $totp) {
			return 1;
		}
	}
	return 0;
}

sub check_usercache {
	my $k = shift;
	my $ms = new Cache::Memcached {
		'servers' => ['127.0.0.1:11211'],
		'debug' => 0,
		'compress_threshold' => 10_000,
	};

	if ($ms->get($k)) {
		$ms->disconnect_all();
		return 1;
	} else {
		$ms->disconnect_all();
		return 0;
	}
}

sub set_usercache {
	my $k = shift;
	my $ms = new Cache::Memcached {
		'servers' => ['127.0.0.1:11211'],
		'debug' => 0,
		'compress_threshold' => 10_000,
	};

	$ms->set($k, "1", 60*60*24);
	$ms->disconnect_all();
}

sub log_request_attributes {
	# This shouldn't be done in production environments!
	# This is only meant for debugging!
	for (keys %RAD_REQUEST) {
		&radiusd::radlog(L_DBG, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
	for (keys %RAD_CHECK) {
		&radiusd::radlog(L_DBG, "RAD_CHECK $_ = $RAD_CHECK{$_}");
	}
	for (keys %RAD_STATE) {
		&radiusd::radlog(L_DBG, "RAD_STATE $_ = $RAD_STATE{$_}");
	}
	for (keys %RAD_REPLY) {
		&radiusd::radlog(L_DBG, "RAD_REPLY $_ = $RAD_REPLY{$_}");
	}
}
