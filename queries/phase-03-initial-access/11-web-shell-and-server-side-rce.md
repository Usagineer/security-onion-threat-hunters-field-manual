# Web Shell / Server-Side RCE — Initial Access

## What this does

Looks for signs of initial-access activity involving Web Shell And Server Side Rce. Use the results with the surrounding host, user, time, and network context before escalating.

> UNVERIFIED: Validate field availability and web-server process names in your deployment before operational use.

```
event.category:process AND process.parent.name:(apache2 OR httpd OR nginx OR w3wp.exe OR php-fpm) AND process.name:(sh OR bash OR cmd.exe OR powershell.exe OR python OR perl OR curl OR wget)
```

```
event.category:process AND process.command_line:(*s_client* OR *mkfifo* OR *"bash -i"* OR *"/dev/tcp/"*)
```

```
event.dataset:zeek.http AND http.request.method:(POST OR GET) AND url.original:(*.php* OR *.jsp* OR *.aspx* OR *.cgi*) | groupby source.ip destination.ip url.original http.response.status_code
```

Start with the web request, then pivot to process creation and the web server's
outbound connections. A 200 response is not evidence that a request was benign;
look for a new child process or network session close to the request timestamp.
