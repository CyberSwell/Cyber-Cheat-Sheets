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
```
arp-scan -l
```
