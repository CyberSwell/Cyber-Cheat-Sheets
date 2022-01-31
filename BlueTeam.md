# BlueTeam
List of non pen tasting stuff. Pen untasters?

# netstat
```bash
netstat -peanut
```
> Use this to hunt for sussy open ports/ processes that shouldn't have an established connection, such as a random Python script.
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
## ps
```bash
ps awwfux
```
- **a:** View all processes
- **ww:** Unlimited width
- **f:** Show process trees
- **u:** Display in user-oriented format
- **x:** Remove "must-have-tty" restriction

## iptables
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
