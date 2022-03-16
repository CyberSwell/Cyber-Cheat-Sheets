# Memory Forensics Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.

## Volatility:
Download (Debian-based Linux):
Install system dependencies
```console
user@kali:@$ sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata
```



## Wireshark:
- `Statistics > Capture File Properties`
  - Time elapsed, number of packets, and capture host information
- `Statistics > Protocol Hierarchy`
  - Ethernet vs WiFi vs Bluetooth
  - Application protocols present (ex: HTTP)
  - Data streams
  - **Filters can be created from protocols by right clicking > "Apply As Filter"**
-  Streams for packets of interest can be analyzed by right clicking > "Follow" > "XYZ Stream"

## TShark:
Basic Syntax:
```bash
tshark -i {interface} -f {captureFilter} -r {inFile} -w {outFile} [options] [filters]
```
Useful Options:
`-T fields -e {fields}`: Specifies output format of "fields" view, fields specified with `-e`.
  - `ip.src`: Source IP address
  - `ip.dst`: Destination IP address
  - `tcp.srcport`: Source TCP port
  - `udp.dstport`: Destination UDP port

## Network Miner:
- `Credentials` tab contains parsed login credentials for users
- `Files` tab contains reassembled files from pcap (web pages, images, certificates)
