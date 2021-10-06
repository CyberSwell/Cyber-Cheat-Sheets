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
