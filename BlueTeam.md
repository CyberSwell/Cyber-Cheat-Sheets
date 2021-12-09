# BlueTeam
List of non-pen tasting stuff. Pen untasters?

## iptables
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
