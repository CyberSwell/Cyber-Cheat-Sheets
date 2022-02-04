# BlueTeam
List of non pen tasting stuff. Pen untasters?

# netstat
```bash
netstat -peanut
```
> Use this to hunt for sussy open ports/ processes that shouldn't have an established connection, such as a random Python script listening on 1337.
- **p:** Display both the PID and the program name
- **e:** Display extended information
- **a:** Display all sockets including ones which are not connected
- **n:** Do not try to resolve the names
- **u:** Display UDP sockets
- **t:** Display TCP sockets

```bash
netstat -vatup 
```
> Was recommended for CCDC competition. Displays udp, tcp, ports awaiting connection, and process. 
```
ss -pant
```
> Silly, provides similar functionality as netstat -vatup

## ps
```bash
ps awwfux
```
- **a:** View all processes
- **ww:** Unlimited width
- **f:** Show process trees
- **u:** Display in user-oriented format
- **x:** Remove "must-have-tty" restriction
> Pipe to grep and search for PID's of unknown connections, rogue bash/sh processes, etc.

## iptables
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
