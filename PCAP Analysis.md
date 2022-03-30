# PCAP Analysis Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.

## Wireshark:
- `Statistics > Capture File Properties`
  - Time elapsed, number of packets, and capture host information
- `Statistics > Protocol Hierarchy`
  - Ethernet vs WiFi vs Bluetooth
  - Application protocols present (ex: HTTP)
  - Data streams
  - **Filters can be created from protocols by right clicking > "Apply As Filter"**
-  Streams for packets of interest can be analyzed by right clicking > "Follow" > "XYZ Stream"
https://www.wireshark.org/docs/man-pages/wireshark-filter.html

## Capinfos:
CLI utility that can provide summary statistics/ information about PCAP, such as size, number of packets, start/end times, etc.
https://www.wireshark.org/docs/man-pages/capinfos.html

```console
foo@bar:~$ capinfos file.pcap
File name:           file.pcap
File type:           ...
File encapsulation:  ...
File timestamp precision:  ...
Packet size limit:   ...
Number of packets:   ...
File size:           ...
Data size:           ...
Capture duration:    ...
First packet time:   ...
Last packet time:    ...
...
```

## Mergecap:
Part of wireshark-common (should be installed alongside wireshark and tshark). Able to merge multiple PCAPs into a single PCAP while preserving frame timestamps. 
https://www.wireshark.org/docs/man-pages/mergecap.html

```console
foo@bar:~$ mergecap -w full.pcap part1.pcap part2.pcap part3.pcap...


```

## TShark:
Tshark man page - https://www.wireshark.org/docs/man-pages/tshark.html

Basic Syntax:
```bash
tshark -i {interface} -f {captureFilter} -r {inFile} -w {outFile} [options] [filters]
```

Useful Options:

`-q`: Supress pcap output when reading a pcap

`-T fields -e {fields}`: Specifies output format of "fields" view, fields specified with `-e`.
  - `ip.src`: Source IP address
  - `ip.dst`: Destination IP address
  - `tcp.srcport`: Source TCP port
  - `udp.dstport`: Destination UDP port

` -z <statistic>`: Summary statistics for PCAP
  - `-z endpoints,type[,filter]`: List endpoints by type (ex: ip, eth)
  - `-z ip_hosts,tree`: List all ip endpoints and number of times occurred in PCAP.
    - Can also use `ip_srcdst` to split up source and destination IP's

## Network Miner:
- `Credentials` tab contains parsed login credentials for users
- `Files` tab contains reassembled files from pcap (web pages, images, certificates)
