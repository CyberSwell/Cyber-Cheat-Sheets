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

Syntax: ```sublist3r -d [domain]```

**crt.sh:** Uses certificate fingerprinting, gives list of certificates registered to a domain.

**OWASP Amass:** https://github.com/OWASP/Amass

# 2a: Scanning
##  Tools:
**arp-scan:** Layer 2 Scanning with ARP requests

Syntax: ```arp-scan -l```

**netdiscover:** Uses ARP protocol to discover hosts on a subnet, similar to arp-scan.
Syntax:```netdiscover -r [CIDR range]```

**nmap:** Network scanning utility, capable of enumerating services running on host along with OS information.

Syntax: ```nmap -[options] [target]```

Suggested Scans:
- ```nmap -sn [target]```**:** Disables port scanning, and instead only checks whether host is alive or not.
  -  Append with ```-o targets.txt | grep "report" | cut -d " " -f 5 > liveTargets.txt``` to create list of live IP addresses at a point in time.
- ```nmap -sS [target]```**:** Performs basic service detection on a target's 1000 most _statistically_ common ports.
- ```nmap -sV -p [ports] [target]```**:** Performs version detection on ports specified. Ignoring known closed ports can significantly speed up scan times.
- ```nmap -A -p [ports] [target]```**:** Performs an aggressive scan involving service detection, version detection, OS fingerprinting, 
script scanning, and traceroute. 
- ```nmap -sS -p- [target]```**:** Scans all TCP ports of all hosts on a network. Useful to check for services running on non-standard ports.
  -  Consider using target list with ```nmap -sS -p- -iL liveHosts.txt```
- ```nmap -sU -p [target]```**:** Begin enumerating UDP ports. Consider using live hosts list.
- ```nmap -sU -p- [target]```**:** Check all UDP ports. Consider using live hosts list.

# 2b: Enumeration
##  Notable Ports:
- **22:** Commonly SSH. Not typically an attack vector, but may indicate credentials could be found on host.
- **80, 8080, 443:** Commonly HTTP & HTTPS. Indicates a web application may be available on the host, or at minimum a web service.
- **139, 445** Commonly SMB shares, historically many exploits that can lead to RCE(ex: MS17-010)
- **111, 135:** Commonly RPC. 

## Tools - Web Apps:
**nikto:** Web vulnerability scanner, can provide preliminary points of interest but may not be effective against Web Application Firewalls (WAF's) and well-secured web apps.

Syntax: ```nikto -h [http(s)://ipaddress]```
- Look for anything hinting at outdated versions, RCE, or overflows.

**gobuster:** Personally preferred over dirbuster & dir. Directory busting tool.
Syntax: `gobuster dir -u [url] -w [wordlist]
- Recommended: SecLists (https://github.com/danielmiessler/SecLists) 
- ```gobuster dir -u [url] -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt```
