# Resources:
PayloadsAllTheThings:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

HackTricks:
https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation

# Initial Enumeration
## System ENumeration
- `systeminfo` command: Look for OS name, OS version, and system type
  - `systeminfo | findstr /B /C:"OS Name" "C:/"OS Version" /C:"System Type"
- `wmic qfe` command: Look for last patches/ quickfixes applied
  - `wmic qfe get Caption,Description,HotFixID,InstalledOn`
- `wmic localdisk` command: Look for attached drives
  - `wmic logicaldisk get caption,description,providername`
  - Find other drives that may contain data to parse through for data

## User Enumeration:
- `whoami`: Check current user
  - `/priv`: Check privileges
  - `/groups`: Check what groups user belongs to (potentially administrative groups)
- `net user`: List users on the machine
  - `net user {name}`: View information about a specific user
- `net localgroup`: View membership of a group
  - Identify potential users to move laterally into

## Network Enumeration:
- `ipconfig`: View TCP/IP configuration of the machine
  - Look for potential dual homing, subnet structure, potential DC as DNS, etc.
- `arp -a`: Check ARP tables for other hosts on the LAN
- `route print`: Check routing tables
  - Check for other subnets that could be pivoted to
- `netstat -ano`: Check current connections and open ports listening

## Password Hunting:
- Passwords in files are very common
  - SAM files
  - Unattended.xml
  - Wifi passwords
    - `netsh wlan show profile`
    - `netsh wlan show prifle <SSID> key=clear`
  - Passwords in Registry
- `findstr /si password *.txt`: Look through .txt files in current directory that contain string "password"
  - Also look for .config, .php, and any other file extensions that may contain passwords.

## Firewall & Antivirus Enumeration:
- `sc query windefend`: Check information about Windows Defender (by default on Windows)
- `sc queryex type= service`: Service query for all services running, look for possible AV's running
- `netsh advfirewall firewall dump`: Show firewall state (may be depricated)
- `netsh firewall show state`: Show state of Firewall
- `netsh firewall show config`: Show firewall config

# Automated Tools:
Executables:
- winPEAS.exe: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
- Seatbelt.exe: https://github.com/GhostPack/Seatbelt
- Watson.exe: https://github.com/rasta-mouse/Watson
- SharpUp.exe: https://github.com/GhostPack/SharpUp

Powershell:
- Sherlock.ps1: https://github.com/rasta-mouse/Sherlock
- Powerup.ps1: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- jaws-enum.ps1: https://github.com/411Hall/JAWS

Other:
- windows-exploit-suggester.py: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- MSF Exploit Suggester module: https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/
