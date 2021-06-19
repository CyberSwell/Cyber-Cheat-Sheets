# INE Penetration Testing Student Learning Path - Notes
This is a collection of notes taken while completing INE's "Penetration Testing Student" learning path.

## Introduction
>(nothing notable for me in this section)

## Networking
### IP
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
- Example: 2002:0000:0000:1234:abcd:ffff:c0a8:0101/64
  - Host: 2002:0000:0000:1234:abcd:ffff:c0a8:0101
  - Subnet: 2002:0000:0000:1234:0000:0000:0000:0000 to 2002:0000:0000:1234:ffff:ffff:ffff:ffff
  - Mask: FFFF:FFFF:FFFF:FFFF::
**Routing**
- Checking routing tables:
  - ```ip route``` - Linux
  - ```route print``` - Windows
  - ```netstat -r``` MacOS

:::
