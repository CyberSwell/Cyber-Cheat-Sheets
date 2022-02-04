# BlueTeam
List of non pen tasting stuff. Pen untasters?

## Monitoring Network Connections
Look for connections to IP's outside of known good subnets, processes that shouldn't have a connection (ex: a random Python script), or anything else that looks sussy.

```bash
netstat -peanut
```
- **p:** Display both the PID and the program name
- **e:** Display extended information
- **a:** Display all sockets including ones which are not connected
- **n:** Do not try to resolve the names
- **u:** Display UDP sockets
- **t:** Display TCP sockets

```bash
netstat -vatup 
```
> Was recommended for CCDC competition by Alec. Displays udp, tcp, ports awaiting connection, and process. 
```
ss -pants
```
> Silly, provides similar functionality as netstat -vatup
- **p:** Display process
- **a:** Display all connection states (not just established)
- **n:** Show port number, don't resolve service name
- **t:** Display TCP sockets
- **s:** Show summary information

## Monitoring Processes
```bash
ps -awwfux
```
> Stewart called this "ps oh dear". Lol, get it?
- **a:** View all processes
- **ww:** Unlimited width
- **f:** Show process trees
- **u:** Display in user-oriented format
- **x:** Remove "must-have-tty" restriction
> Pipe to grep and search for PID's of unknown connections, rogue bash/sh processes, etc.

## Firewall Rules
### iptables
Tables (-t)
- filtering (default): Used for packet filtering
- nat: Used for address translation

Chains
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
