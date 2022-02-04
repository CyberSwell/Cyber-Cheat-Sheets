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

## Firewalls
### Netfilter Hooks & iptables chains
- NF_IP_PRE_ROUTING: Triggers PREROUTING chain, occurs as soon as packet arrives at NIC, before processed by any other hook.
- NF_IP_LOCAL_IN: Triggers INPUT chain, after incoming packet arrives in system (if destined for it).
- NF_IP_FORWARD: FORWARD chain triggered if packet is supposed to be forwarded to another host.
- NF_IP_OUT: OUTPUT triggered by traffic going out as soon as it hits network stack.
- NF_IP_POST_ROUTING: POSTROUTING chain triggered as traffic going out, right before being put on wire.

### iptables
Tables (-t):
- filtering (default): Used for packet filtering
- nat: Used for address translation

Rules:
- `sudo iptables {table} -{A|I|D} {chain} {OPTIONS} -j {ACTION}
  - A: Add to end of chain
  - I: Insert in beginning of chain
  - D: Delete matching rule (Alternatively can `iptables -D {chain} {ruleNumber}


Examples:
```bash
# For incoming packets (-A INPUT) from host (-s 192.168.0.1) drop them (-j DROP)
sudo iptables -A INPUT -s 192.168.0.1 -j DROP
```
