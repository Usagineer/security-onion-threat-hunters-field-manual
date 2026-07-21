# Email — Initial Access

```
event.dataset:zeek.smtp | groupby source.ip destination.ip smtp.mailfrom smtp.rcptto
```

```
event.dataset:zeek.smtp | groupby smtp.mailfrom smtp.subject
```

```
event.dataset:zeek.files AND (source.ip:<MAIL_GW> OR destination.ip:<MAIL_GW>) | groupby file.name file.mime_type
```
