# List of resources for Cyber CTF's

## Set up autorecon
https://github.com/Tib3rius/AutoRecon

``` console
sudo apt install python3
sudo apt install python3-pip
sudo apt install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
alias sudo="sudo env \"PATH=$PATH\""
sudo visudo /etc/sudoers
# Set the following:
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/[username]/.local/bin"
sudo apt install seclists curl enum4linux feroxbuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
pipx install git+https://github.com/Tib3rius/AutoRecon.git

usage: autorecon    [-h] [-t TARGET_FILE] [-ct <number>] [-cs <number>]
                    [--profile PROFILE_NAME] [-o OUTPUT_DIR] [--single-target]
                    [--only-scans-dir] [--heartbeat HEARTBEAT]
                    [--nmap NMAP | --nmap-append NMAP_APPEND] [-v]
                    [--disable-sanity-checks]
                    [targets [targets ...]]
```


## Determine Ciphers:
https://www.boxentriq.com/code-breaking/cipher-identifier

## Cracking RSA:
https://github.com/Ganapati/RsaCtfTool
