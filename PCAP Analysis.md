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

## Network Miner:
- `Credentials` tab contains parsed login credentials for users
- `Files` tab contains reassembled files from pcap
