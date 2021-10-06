# Resources:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

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
- 
