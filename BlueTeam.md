# BlueTeam
List of non-pen tasting stuff. Pen untasters?

## ps
```bash
# View all processes (a) unlimited width (ww) with process trees (f) and user-oriented format (u) without "must-have-tty" restriction (x)
ps awwfux
```

## iptables
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
