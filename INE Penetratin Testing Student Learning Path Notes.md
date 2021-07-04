# INE Penetration Testing Student Learning Path - Notes  
This is a collection of notes taken while completing INE's "Penetration Testing Student" learning path.  

# Table of Contents:
Background Information:  
[I. Introduction](#i-introduction)  
[II. Networking](#ii-networking)  
[III. Web Applications](#iii-web-applications)

Penetration Testing Lifecycle:  
[1. Information Gathering](#1-information-gathering)  
[2. Footprinting & Scanning](#2-footprinting--scanning)  
[3. Vulnerability Assessment](#3-vulnerability-assessment)  
[4. Exploitation](#4-exploitation)  
[5. Reporting](#5-reporting)  

## I. Introduction
<details>
  <summary>Introductory information on pentesting</summary>
  
>(nothing notable for me in this section)  
</details>
  
## II. Networking
<details>
  <summary>Introductory information on IP, Routing, Switching, Firewalls, and IDS/IPS's</summary>
  
### II.1 IP
**IPV4** 
- Made up of 4 bytes (octets) delineated with ".", 64 bits total
- Contains a network prefix and host portion of IP address
- Example: 192.168.1.5/24
  - Host: 192.168.1.5
  - Subnet: 192.168.1.0
  - Mask: 255.255.255.0


**IPV6**
- Made up of 8 groups of 2 bytes (in hex) delineated with ":", 128 bits total.
- First half is network, second half is host.
  - Network portion has 6 bytes (48 bits) of Global Unicast Address, and 2 bytes (16 bits) of Subnet ID.
- Three scopes:
  - Global Unicast - Internet-routed
  - Unique Local - Internally routable, but not routed on internet.
  - Link Local - Cannot be routed internally or externally
- Example: 2002:0000:0000:1200:acbd:ffff:c0a8:0101/64
  - Host: 2002:0000:0000:1200:acbd:ffff:c0a8:0101
  - Subnet: 2002:0000:0000:1200:0000:0000:0000:0000 to 2002:0000:0000:1200:ffff:ffff:ffff:ffff
  - Mask: FFFF:FFFF:FFFF:FFFF::


### II.2 Routing
- Checking routing tables:
  - Linux:
    ```bash
    ip route
    ```  
  - Windows:
    ```
    route print
    ```  
  - MacOS:
    ```
    netstat -r
    ```  
  - Adding a route:
    - Linux:  
      ```
      ip route add <subnet> via <gateway>
      ```

### II.3 Link Layer
- MAC addresses  
  - 6 bytes (48 bits), written in hex form.
- Finding MAC address:  
  - Windows:  
    ```
    ipconfig /all
    ```  
  - Linux/*nix:
    ```
    ifconfig
    or
    ip addr
    ```  
- Forwarding tables:
  - Also called Content Addressable Memory (CAM) table.
  - Created as the switch obtains new data frames.
  - Kept on Switches, contain MAC address, interface, and TTL.
    - TTL determines how long entries stay in table (since CAM table has finite size)
  - If two hosts have the same interfaces, then most likely connected via another switch.
  - Address Resolution Protocl (ARP):
    - Sends frame to broadcast address seeking MAC address corresponding to a specific IP address.
    - ARP cache kept on hosts
      - Windows:
        ```
        arp -a
        ```
      - Linux:
        ```
        ip neighbor
        ```
      - \*nix:
        ```
        arp
        ```
### II.4 TCP/UDP
- TCP is connection-oriented, UDP connectionless.
- Processes on a host are identified with \<IP\>:\<PORT\>.
- Ports 0-1023 are **well-known** ports.
- IANA Port Assignments: http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
- Daemon: A program that runs a service (ex: Web server daemon runs Apache2 web service)
- Check current listening ports and TCP connections:
  - Windows:
    ```
    netstat -ano
    ```
  - Linux:
    ```
    netstat -tunp
    ```
  - \*nix:
    ```
    netsat -p tcp -p udp
    lsof -n i4TCP -4 UDP
    ```
### II.5 Firewalls and Network Defense
- Firewalls:
  - Three types:
    - Packet Filtering: Takes into consideration source and destination IP address & port, along with protocol. Does not look at packet contents, and does not protect against application-layer attacks.
      - Typically rules set to **allow**, **drop**, or **deny**
        - Unlike **deny**, **drop** does not send a response when packet is not forwarded. 
    - Application Level/ Deep Packet Inspection:
      - Utilized by IDS's, checks actual packet data. Capable of identifying port scans, SQL injections, buffer overflow, etc.
- IDS:
  - Host based or network based (HIDS vs NIDS).
  - NIDS typically placed within a network/ subnet where security levels differ.
  - HIDS monitor application logs, filesystem changes, OS config changes, etc.
- IPS:
  - Capable of dropping packets and acting when malicious activity is detected.  
- Spotting network defenses:
  - No responses to TCP SYN may indicate packets dropped
  - TCP RST/ACK response to SYN  

### II.6 Wireshark
- Filters
  - Capture filters: Filtering occurs during the actual capture of packets.
  - Display filters: Filters only show certain packets obtained during the capture.
    - \<protocolname\>.[field][operand value]
    - ip.addr == 192.168.0.1  

### II.7 Data Exfiltration Lab
- https://github.com/stufus/egresscheck-framework.git
- Can look for interesting files with:
  ```
  dir /s /b [filename]
  ```
  - The "/s" flag recurses through subdirectories during the search.
  - The "/b" flag provides a "bare" list of directories and files.
- Can check for scripting languages with:
  ```
  python --version
  powershell ls
  ```
- Simple python http server:
  ``` bash
  python -m SimpleHTTPServer 8080
  ```
- Start python http server in directory for PacketWhisper (https://github.com/TryCatchHCF/PacketWhisper)
  - May also be useful to host the zip: https://github.com/TryCatchHCF/PacketWhisper/archive/master.zip
- Navigate to hosted python server on target machine
- Download master.zip, extract locally.
- On target machine, use ```python packetwhisper.py```
- Using "Random SUbdomain FQDNs" transfer mode and "cloudfront_prefixes" cipher on the victim machine, we can put the file back together on the attacker machine by saving the pcap, using ```python packetwhisper.py``` with the second mode, and select the same ciphers.
  </details>

  
## III. Web Applications
<details>
  <summary>Introductory information on web applications</summary>

### III.1: Introduction
- Web applications run on web servers, and are accessed by clients over web browsers.
- Calculations or dynamic content can be generated either client or server side.
  
### III.2: HTTP Protocol Basics
- HTTP is a client-server protocol, is used to transfer web pages and web app data on top of TCP.
- Communication is composed of HTTP requests by the client, and http responses by the server.
HTTP Message Format:
  - Headers\r\n
  - \r\n
  - Message Body\r\n
  > \r is `carriage return`, and \n is `newline` 
  
HTTP Requests:
- Request method: states type of request
- Path and protocol version
- Host: URI of the resource
- User-Agent string: Details of the client, such as web browser, version, and OS.
- Accept header: The type of document that is expected in server's response.
- Accept-Language: A specifc human language, like `en-US`.
- Accept-Encoding: Accepted encoding of the document, such as `gzip, deflate`.
- Connection: Whether future communications will reuse current connection, or will require another TCP connection to be established.

HTTP Responses:
- Status-Line: Protocol version, status code, and textual meaning of status code.
- Date
- Headers: May include headers such as `Cache-Control`
- Content-Type: The type of content included in the response.
- Content-Encoding: How the content of the response is encoded
- Server: Header of the server that generated the content (ex: Apache)
  - An optional field, may be useful with enumeration/ may disclose sensitive information about server.
- Content-Length: Length of the message body in bytes.

  
HTTPS:
- HTTP over SSL/TLS
- Protects against third parties viewing message contents, NOT against web application flaws (such as SQLi)
 
### III.3: Analyzing HTTP Connections
Techniques:
- Using **netcat** to manually craft HTTP requests and viewing the responses
  ``` console
  foobar@kali:~$ nc -v thon.org 80
  DNS fwd/rev mismatch: thon.org != server-143-204-146-83.ewr52.r.cloudfront.net
  DNS fwd/rev mismatch: thon.org != server-143-204-146-39.ewr52.r.cloudfront.net
  DNS fwd/rev mismatch: thon.org != server-143-204-146-67.ewr52.r.cloudfront.net
  DNS fwd/rev mismatch: thon.org != server-143-204-146-64.ewr52.r.cloudfront.net
  thon.org [143.204.146.83] 80 (http) open
  GET / HTTP/1.1
  Host: www.thon.org

  HTTP/1.1 301 Moved Permanently
  Server: CloudFront
  Date: Sun, 04 Jul 2021 20:42:40 GMT
  Content-Type: text/html
  Content-Length: 183
  Connection: keep-alive
  Location: https://www.thon.org/
  X-Cache: Redirect from cloudfront
  Via: 1.1 72e01c53ea1f597217a963cf6671454c.cloudfront.net (CloudFront)
  X-Amz-Cf-Pop: EWR52-C2
  X-Amz-Cf-Id: 54xexutXOxfEXBEO3kobkXDEPHMM-4m1mjCAr36dSgQd-5-mrkimUQ==

  <html>
  <head><title>301 Moved Permanently</title></head>
  <body bgcolor="white">
  <center><h1>301 Moved Permanently</h1></center>
  <hr><center>CloudFront</center>
  </body>
  </html>
  ```
  > Instead of `GET`, you can use other HTTP methods, such as `OPTIONS`, in order to enumerate what HTTP methods are available for a request.
  > You can also specify multiple fields in the request, and just hit `enter` twice once you are done crafting the request.

  
  
</details>  
  
  
## 1. Information Gathering
### 1.1 OSINT

### 1.2 Subdomain Enumeration
Goals:
- Enumerate internet attack surface for websites that may be vulnerable to attack.  

Passive Techniques:
- Google Dorking
  - ```site: domain.com```
- Websites:
  - ```dnsdumpster.com```, ```crt.sh```
- Sublist3r
  ``` bash
  sublist3r -d domain.com
  ```
- "Certificate Subject Alt Name" field of SSL Certificate

Active Techniques
- Gobuster
  ``` bash
  gobuster dir -u [url] -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
- Amass
  - https://github.com/OWASP/Amass/blob/master/doc/user_guide.md
  ``` bash
  sudo apt install snapd
  snapd install amass
  amass
  ```
  
## 2. Footprinting & Scanning
### 2.1 Mapping Networks
Goals:
- Determine in-scope and out-of-scope devices
- Identify in-scope subnet topologies

Techniques:
- Ping Sweeping: Send ICMP Type 8 (echo request) to host, response indicates host is alive
  ``` bash
  fping -a -g [IP RANGE]
  -a: only show alive hosts
  -g: ping sweep, not normal ping
  ```
- Nmap: -sn flag for ping sweeping.
  ``` bash
  nmap -sn [IP RANGE]
  OR
  nmap -sn -iL hostlist.txt
  ```
### 2.2 OS Fingerprinting
Goals:
- Different OS's have different implementation of network stack.
- Signatures of responses to requests can be compared to a databse of known OS signatures.
- Identify what OS a host is running.

Techniques:
- Nmap: -Pn flag to skip ping scan, -O for OS discovery.
  ``` bash
  nmap -Pn -O [targets]
  ```

### 2.3 Port Scanning
Goals:
- Enumerate daemons and services running on network nodes
- Look for ACK flag for open port, RST + ACK for closed port


Techniques:
- TCP SYN Scan: SYN sent, SYN + ACK received if port open, RST sent back to avoid full connection.
  - Daemon does not log connection
  ``` bash
  nmap -sS [TARGET]
  (NOTE: nmap uses -sS by default)
  ```
- TCP Connect: Full TCP connection made
  ``` bash
  nmap -sT [TARGET]
  ```
- Version Detection Scan: TCP Connect scan with additional probes to enumerate application listening. Reads banner sent by daemon.
  - ```tcpwrapped``` indicates TCP handshake was completed, but remote host closed connection without receiving any data (application protected by ```tcpwrapper``` - could be IPS or firewall)
  ``` bash
  nmap -sV [TARGET]
  ```
- Specifying Ports: ```-p``` flag, with port range specified as comma separated list (ex: ```-p 80,443,8080```) or an interval (ex: ```-p 1-65535```)
- Scripts:
  - Using `--script [scriptname]` flag.
  - The `vulners` script (invoked with `--script vulners`), provides vulnerability info similar to Nessus.
  - https://github.com/vulnersCom/nmap-vulners
  
## 3. Vulnerability Assessment
Goals:
- Discover known vulnerabilities on a system.
- Discover service misconfigurations.
 
Techniques:
- Automated Tools:
  - Nessus: Composed of a client, which configures scans, and server, which carries out the scans.
    - Also sends out probes to verify if vulnerability exists
## 4. Exploitation
  
## 5. Reporting
