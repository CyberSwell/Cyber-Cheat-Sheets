# BlueTeam
List of non-pen tasting stuff. Pen untasters?

# netstat
```bash
netstat -ano
```
- **a:** Show all listening and non-listening sockets
- **n:** Show numerical IP's instead of hostnames
- **o:** Include information about network timers

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
