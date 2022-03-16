# Memory Forensics Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.

```console
user@kali:~$ 
```

## 1. Volatility:
### 1.1 Download & Setup(Debian-based Linux):
#### Install system dependencies
```console
user@kali:~$ sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata
```

#### Install pip for Python 2
```console
user@kali:~$ sudo apt install -y python2 python2.7-dev libpython2-dev
user@kali:~$ curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
user@kali:~$ sudo python2 get-pip.py
user@kali:~$ sudo python2 -m pip install -U setuptools wheel
```

#### Install Volatility 2 and its Python 2 dependencies
```console
user@kali:~$ python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
user@kali:~$ sudo python2 -m pip install yara
user@kali:~$ sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
user@kali:~$ python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git
```

#### Install pip for Python 3
```console
user@kali:~$ sudo apt install -y python3 python3-dev libpython3-dev python3-pip python3-setuptools python3-wheel
```

#### Install Volatility 3 and its Python 3 dependencies
```console
user@kali:~$ python3 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
user@kali:~$ python3 -m pip install -U git+https://github.com/volatilityfoundation/volatility3.git
```

#### Add your user bin to PATH, so explicit path to `vol.py` does not need to be used for running program
- Replace "$USERNAME" with your actual username
Bash:
```console
user@kali:~$ echo 'export PATH=/home/$USERNAME/.local/bin:$PATH' >> ~/.bashrc
user@kali:~$ . ~/.bashrc
```

Zsh:
```console
user@kali:~$ echo 'export PATH=/home/$USERNAME/.local/bin:$PATH' >> ~/.zshrc
user@kali:~$ . ~/.zshrc
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
