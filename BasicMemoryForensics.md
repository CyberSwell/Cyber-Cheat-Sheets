# Memory Forensics Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.

## 1. Volatility:
### 1.1 Download & Setup:
<details>
  <summary>Debian-based Linux (like Kali)</summary>
  
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
</details>

### 1.2 Basic Syntax
```console
user@kali:~$ vol.py {options} {plugin}
```
- `-f {dumpfile}`: specifies the dumpfile Volatility should analyze.
- `--profile={profilename}`: Operating system profile Volatility should use to analyze. Can be obtained with the `imageinfo` plugin
- `{plugin}`: Volatility plugin to be used for analysis.


### 1.3 Volitility Plugins w/ Examples
#### imageinfo
- Used for obtaining basic information about the host, such as recommended volatility OS profiles, number of processors, date & time, and other important contextual information about the device.

#### pslist
- Gives list of running processes
  - Process ID (PID) useful for identifying different instances of a process.
  - Parent PID (PPID) useful for determining what processes spawned/launched other processes.

#### pstree
- Alternative to pslist, visually shows processes and subprocesses along with their PID and PPID's.

#### psxview
- Enumerates potentially hidden processes, could discover processes not found with `pslist` and `pstree`.
