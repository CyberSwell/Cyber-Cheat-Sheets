# INE Penetration Testing Student Learning Path - Notes
This is a collection of notes taken while completing INE's "Penetration Testing Student" learning path.

## 1. Introduction
>(nothing notable for me in this section)

## 2. Networking
### 2.1 IP
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


### 2.2 Routing
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

### 2.3 Link Layer
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
### 2.4 TCP/UDP
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
### 2.5 Firewalls and Network Defense
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
