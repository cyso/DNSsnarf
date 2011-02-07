#
# Regular cron jobs for the dnssnarf package
#
0 4	* * *	root	[ -x /usr/bin/dnssnarf_maintenance ] && /usr/bin/dnssnarf_maintenance
