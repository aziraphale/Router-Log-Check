MikroTik Router SSH Login Failure Banning Script
===========================================================

I wrote this script because MikroTik routers don't have a fail2ban-type system whereby IP addresses who repeatedly fail SSH logins are temporarily banned from making further connections. Due to the high numbers of SSH brute-force attacks that our main router is hit by on a daily basis, this script was written to monitor the router's log file and automatically ban IP addresses which suffer too many login failures in a short space of time, thus improving security and reducing the spam in our log file.


Requirements
-------------------
- PHP, MikroTik router, all the obvious stuff...
- The [PHP SSH2 extension](http://www.php.net/manual/en/book.ssh2.php)
    - On Ubuntu this is simply `sudo apt-get install libssh2-php`
    - On other distributions you may have to [install via PECL](http://pecl.php.net/package/ssh2) (`pecl install ssh2`, although it's only in beta at the moment, so PECL will want you to specify a version, e.g. `pecl install channel://pecl.php.net/ssh2-0.12`). Note that installing via PECL will require that you first have the [libssh2 library](http://www.libssh2.org/) installed.


Configuration
-------------------
In addition to changing the (fully-documented) configuration variables at the top of the script, your router must have a few firewall rules in place to facilitate the blocking process (add these to ip/firewall/filter):

 * The first rule causes the router to add an IP address to the "inbound-blacklist" address list when a connection is made to it on a special port number (so that, for example, this script can initiate a connection to 1.2.3.4:31337, which will cause the address 1.2.3.4 to be added to the inbound-blacklist address list:

        chain=forward action=add-dst-to-address-list protocol=tcp \
            address-list=inbound-blacklist address-list-timeout=1d dst-port=31337

 * The other two rules drop all inbound traffic from an IP address on the blacklist:

        chain=input     action=drop   src-address-list=inbound-blacklist
        chain=forward   action=drop   src-address-list=inbound-blacklist


Notes
-------------------
Yes, this script should support IPv6 as well as IPv4, however the above firewall rules will need adding to. Specifically, the same sort of rules should be added to the IPv6 firewall (ipv6/firewall/filter). Note that this has not been tested, as we have yet to have any SSH hack attempts coming from IPv6 addresses, so it's a very low priority for us.
