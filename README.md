![DNSSnarf Logo](http://github.com/Cysource/DNSSnarf/raw/master/logo/dnssnarf.png)

Description
===========

DNSsnarf, a DNS statistics gatherer for use with any DNS daemon.


DNSSNARF(1)
===========

NAME
       dnssnarf - a DNS statistics gatherer for use with any DNS daemon.

SYNOPSIS
       dnssnarf [-f] [-i INTERFACE]

DESCRIPTION
       This manual page documents briefly describes the dnssnarf daemon.

       The  dnssnarf  daemon  should  be  started  and stopped via its init.d script, which is automatically installed by the package.  Configuration options are specified in /etc/default/dnssnarf.  By
       default upon starting, the daemon will immediately fork itself and run into the background.

       -f     Runs DNSsnarf in the foreground.

       -i INTERFACE
              Run DNSsnarf on the specified interface, instead of the system default.

       Use the dnssnarfclient tool to retrieve the statistics that dnssnarf gathers.

SEE ALSO
       dnssnarfclient(1).

AUTHOR
       dnssnarf was written by Peter Geissler <peter.geissler@cyso.nl> and Nick Douma <nick.douma@cyso.nl>

       This manual page was written by Nick Douma <nick.douma@cyso.nl> for Cyso, and is licensed under GPLv2.


DNSSNARFCLIENT(1)
=================

NAME
       dnssnarfclient - a tools to read statistics from DNSsnarf

SYNOPSIS
       dnssnarfclient -r RECORDTYPE -q | -a | -t

DESCRIPTION
       This manual page documents briefly describes the dnssnarfclient command and its options.

       dnssnarfclient  connects  with  a running dnssnarf daemon, using shared memory. It can then report statistics about DNS record types, and how many times a request has been received and processed
       for a specific type since the start of the dnssnarf daemon.

       -r RECORDTYPE
              Type of DNS record to receive statistics for. Can be any of: A, AAAA, CNAME, MB, MD, MF, MG, MR, MX, NAPTR, NS, PTR, RP, SOA, SPF, SRV, SSHFP, TX. Use all to sum up all record types.

       -q     Count of incoming packets.

       -a     Count of outgoing packets.

       -t     Count of incoming and outgoing packets combined.

SEE ALSO
       dnssnarf(1),

AUTHOR
       dnssnarf was written by Peter Geissler <peter.geissler@cyso.nl> and Nick Douma <nick.douma@cyso.nl>

       This manual page was written by Nick Douma <nick.douma@cyso.nl> for Cyso, and is licensed under GPLv2.
