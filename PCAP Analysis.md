# PCAP Analysis Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.
## **GUI TOOLS**
### Wireshark:

Filters: https://www.wireshark.org/docs/man-pages/wireshark-filter.html

- `Statistics > Capture File Properties`
  - Time elapsed, number of packets, and capture host information
- `Statistics > Protocol Hierarchy`
  - Ethernet vs WiFi vs Bluetooth
  - Application protocols present (ex: HTTP)
  - Data streams
  - **Filters can be created from protocols by right clicking > "Apply As Filter"**
-  Streams for packets of interest can be analyzed by right clicking > "Follow" > "XYZ Stream"


### Network Miner:
- `Credentials` tab contains parsed login credentials for users
- `Files` tab contains reassembled files from pcap (web pages, images, certificates)

## **CLI TOOLS**

### Pcapfix:

https://f00l.de/pcapfix/

Occasionally, I have received pcaps that appeared "broken or corrupt" due to packets having outrageous lengths, noticed with the following error when attempting to open up the PCAP with any utility:

```
An error occurred after reading xyz packets from "{FILE}".
{UTILITY}: The file "{FILE}" appears to be damaged or corrupt.
(pcap: File has {HUGENUMBER}-byte packet, bigger than maximum of 262144)
```

Why does this happen? Man idk. How does pcapfix repair it? Also wizardry to me. Maybe one day when I'm older I can update this.

Installation:
<details>
  <summary>Via .tar.gz for Linux:</summary>
  
1. Download from https://f00l.de/pcapfix/
  
2. Unzip the .tar.gz
```console
foo@bar:~$ tar -xzvf pcapfix-1.1.7.tar.gz
pcapfix-1.1.7/
pcapfix-1.1.7/pcapfix.h
pcapfix-1.1.7/Makefile
.
.
.
```
  
3. Compile & install the binary
  
```console
foo@bar:~$ make
cc   -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wall -Wextra -std=gnu99 -pedantic -Wformat -Werror=format-security -g -c pcap.c -o pcap.o
cc   -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wall -Wextra -std=gnu99 -pedantic -Wformat -Werror=format-security -g -c pcap_kuznet.c -o pcap_kuznet.o
cc   -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wall -Wextra -std=gnu99 -pedantic -Wformat -Werror=format-security -g -c pcapng.c -o pcapng.occ   -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wall -Wextra -std=gnu99 -pedantic -Wformat -Werror=format-security -g -Wl,-z,relro pcapfix.c pcap.o pcap_kuznet.o pcapng.o -o pcapfix
foo@bar:~$ sudo make install
[sudo] password for foo:
install -pDm755 pcapfix /usr/bin/pcapfix
install -pDm644 pcapfix.1 /usr/share/man/man1/pcapfix.1
```
  
</details>


<details>
  <summary>Standalone Windows exe:</summary>
  
  # 🤡LMAO sike🤡

</details>


Usage:
```console
foo@bar:~$ pcapfix -o {outfile} broken.pcap
pcapfix 1.1.7 (c) 2012-2021 Robert Krause

[*] Reading from file: broken.pcap
[*] Writing to file: {outfile}
[*] File size: ...
[+] This is a PCAP file.
[*] Analyzing Global Header...
[+] The global pcap header seems to be fine!
[*] Analyzing packets...
[*] Progress:  20.00 %
[*] Progress:  40.00 %
[*] Progress:  60.00 %
[*] Progress:  80.00 %
[*] Progress: 100.00 %
[*] Wrote 1577883 packets to file.
[+] SUCCESS: {NUM} Corruption(s) fixed!
```

### Capinfos:
https://www.wireshark.org/docs/man-pages/capinfos.html

CLI utility that can provide summary statistics/ information about PCAP, such as size, number of packets, start/end times, etc.

```console
foo@bar:~$ capinfos file.pcap
File name:           file.pcap
File type:           ...
File encapsulation:  ...
File timestamp precision:  ...
Packet size limit:   ...
Number of packets:   ...
File size:           ...
.
.
.
```

### Mergecap:
https://www.wireshark.org/docs/man-pages/mergecap.html

Part of wireshark-common (should be installed alongside wireshark and tshark). Able to merge multiple PCAPs into a single PCAP while preserving frame timestamps. 

```console
foo@bar:~$ mergecap -w full.pcap part1.pcap part2.pcap part3.pcap...
```

### TShark:
https://www.wireshark.org/docs/man-pages/tshark.html

Basic Syntax:
```console
foo@bar:~$ tshark -i {interface} -f {captureFilter} -r {inFile} -w {outFile} [options] [filters]
```

Useful Options:

`-q`: Supress pcap output when reading a pcap (should almost always be used when using tshark to do analysis)

`-T fields -e {fields}`: Specifies output format of "fields" view, fields specified with `-e`.
  - `ip.src`: Source IP address
  - `ip.dst`: Destination IP address
  - `tcp.srcport`: Source TCP port
  - `udp.dstport`: Destination UDP port

` -z <statistic>`: Summary statistics for PCAP
  - `-z endpoints,type[,filter]`: List endpoints by type (ex: ip, eth)
  - `-z ip_hosts,tree`: List all ip endpoints and number of times occurred in PCAP.
    - Can also use `ip_srcdst` to split up source and destination IP's, or `dests` to return all TCP/UDP ports per IP.


