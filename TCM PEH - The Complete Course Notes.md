# 1: Information Gathering
## 1.1: Email Gathering Tools
1. theharvester
2. hunter.io

## 1.2: Subdomains
### Goals:
1. Find specific subdomains of interest
  1. ex: zoom.domain.com, dev.domain.com, mail.domain.com, vpn.domain.com
### Tools:
1. **sublist3r:** Looks through DNS records and search engines
```
sublist3r -d [domain]
```
2. **crt.sh:** Uses certificate fingerprinting, gives list of certificates registered to a domain.
3. **OWASP Amass:** https://github.com/OWASP/Amass
