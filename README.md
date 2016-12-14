VPN OTP
=======

Optional OTP freeradius perl plugin code for VPNs which support RADIUS Access-Challenge.

## Feature

Authenticate VPN users with optional TOTP step. A user will be prompted for TOTP step if
- 2FA is globally enforced or is turned on (configured) in account setting
- The account is priviledged and 2FA is required

but the user will be exempted from 2FA if he was authenticated in last 24 hours (the time can be changed).
The exemption can be based on user's connecting IP address, or unique device id. However, there is no such unique device id
can be used so far.

RADIUS attribute `Filter-Id` is used to carry group information.

This code can be used for
- OpenVPN Access Server
- OpenConnect server
- SonicWALL SMA
- Array AG
- any other VPNs that support RADIUS Access-Challenge

## Requirement

The code is developed for Freeradius 3.0.x. It can be used on Freeradius 2.x with minor tweak

The following perl modules are required:
- Cache::Memcached
- Authen::OATH
- Convert::Base32

Authen::OATH is used for TOTP verification. You can replace it with a little of code to save a dependency.

A `memcached` is required running on 127.0.0.1:11211.

## How to test

The example configuration files are for test only.

Put perl code into `/etc/freeradius/perl/`, and configure freeradius as example configuration files
- define a perl module instance
- define an auth server and reference the perl instance

Then, you reference this radius server in VPN server's configuration.

Extend dictionary, by adding the following line to `/etc/freeradius/dictionary`
```
ATTRIBUTE        TOTP-Secret             3000    string
```

Add test users into `/etc/freeradius/mods-config/files/authorize`, before DEFAULT things, such as

```
bob	Cleartext-Password := "bobsecret", TOTP-Secret := "{TOTP_TOKEN}48656c6c6f21deadbeef48656c6c6f21deadbeef"
```

Beware: this code use 40x hex string format (corresponding to 32x base32 string) for TOTP secret.

Convert BASE32 string to hex string
```
echo -n <base32_string> | base32 -d | hexdump -v -e '/1 "%02x"'
```

You can try online TOTP qrcode generator, for example
- Random secret: http://www.xanxys.net/totp/
- Specify secret: http://dan.hersam.com/tools/gen-qr-code.html

## How to use in production server

Your site most probably uses LDAP and you have to tweak a little. You need to
- define a freeradius LDAP module instance
- reference the LDAP module instance instead of `files` and `pap`

How to define freeradius LDAP module instance is beyond the scope of this document. Please refer to freeradius
document.

You need to add an `update` section into the LDAP instance definition

```
update {
	control:Filter-Id += 'memberOf'
	control:TOTP-Secret += 'carLicense'
}
```

Here we use a seldom used LDAP attribute `carLicense` to store TOTP secret. LDAP instance will populate RADIUS 
attribute `TOTP-Secret` with LDAP attribute `carLicense`.  You can use other attribute however.

## Note on groups

VPN servers can use LDAP group information directly, but it's not optimal when you have a lot of groups. It's
painful to define VPN access rules for so many groups. By using MapGroup.pm, you can map LDAP groups into a few
groups, thus make life easier.


## Copyright

Copyright (C) 2014-2016 Wang Jian <larkwang@gmail.com>

## License

This code is licensed under GPL v2. See `LICENSE` file.
