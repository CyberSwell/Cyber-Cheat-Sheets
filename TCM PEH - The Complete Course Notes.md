# 1: Information Gathering
##  1.1: Email Gathering Tools
- theharvester
- hunter.io

##  1.2: Subdomains
### Goals:
- Find specific subdomains of interest
  - ex: zoom.domain.com, dev.domain.com, mail.domain.com, vpn.domain.com
### Tools:
**sublist3r:** Looks through DNS records and search engines
```
sublist3r -d [domain]
```
**crt.sh:** Uses certificate fingerprinting, gives list of certificates registered to a domain.
**OWASP Amass:** https://github.com/OWASP/Amass

# 2: Scanning & Enumeration
##  Tools:
**arp-scan:** Layer 2 Scanning with ARP requests
Syntax: ```arp-scan -l```

**netdiscover:** Uses ARP protocol to discover hosts on a subnet, similar to arp-scan.
Syntax:```netdiscover -r [CIDR range]```

**nmap:** Network scanning utility, capable of enumerating services running on host along with OS information.

Syntax: ```nmap -[options] [target]```

Suggested Scans:
- ```nmap -sn [target]```**:** Disables port scanning, only checks whether host is alive or not.
  -  Append with ```-o targets.txt | grep "report" | cut -d " " -f 5 > liveTargets.txt``` to create list of live IP addresses at a point in time.
- ```nmap -sS [target]```**:** Performs basic service detection on a target's 1000 most _statistically_ common ports.
- ```nmap -sV -p [ports] [target]```**:** Performs version detection on ports specified. Ignoring known closed ports can significantly speed up scan times.
- ```nmap -A -p [ports] [target]```**:** Performs an aggressive scan involving service detection, version detection, OS fingerprinting, 
script scanning, and traceroute. 
