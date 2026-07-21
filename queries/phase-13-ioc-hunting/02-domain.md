# IOC — Domain

```
dns.question.name:*<ioc_domain>* OR tls.client.server_name:*<ioc_domain>* OR url.domain:*<ioc_domain>*
```

```
event.dataset:zeek.dns AND dns.question.name:*<ioc_domain>* | groupby source.ip
```

```
event.dataset:zeek.dns AND dns.question.name:*<ioc_domain>* | groupby dns.answers
```
