# Memory Forensics Techniques
Methodologies picked up from coursework, CTF's, and forensic challenges.

## 1. Volatility:
### 1.1 Download & Setup(Debian-based Linux):
<details>
  <summary>Step-by-step instructions for downloading and setting up Volatility( ** click to expand ** )</summary>
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

### 1.3 Volitility Modules w/ Examples
#### imageinfo
- Used for obtaining 
