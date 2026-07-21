# FTP — Initial Access

```
event.dataset:zeek.conn AND destination.port:21 AND NOT source.ip:"10.0.0.0/8" AND destination.ip:"10.0.0.0/8"
```

```
event.dataset:zeek.ftp | groupby source.ip destination.ip ftp.command ftp.reply_code
```

```
event.dataset:zeek.ftp AND ftp.reply_code:530 | groupby source.ip destination.ip
```
