## Shodan Dorks

<kbd>Generic Queries

- `ssl:target.* 200`
- `Ssl.cert.subject.CN:"target.*" 200`
- `hostname:"target"`
- `org:target`
- `http.title:"index of/"`
- `http.title:"gitlab"`
- `"230 login successful" port:"21"`
- `http.title:"Admin"`

---

## More in detail

<kbd>Finding Exposed Admin Panels</kbd>
```shodan
http.title:"admin" OR http.title:"login" OR http.html:"admin" hostname:"example.com"
```

<kbd>Detecting Open Elasticsearch Instances</kbd>
```shodan
product:"ElasticSearch" port:9200 hostname:"example.com"
```

<kbd>Exposed Databases (MongoDB)</kbd>
```shodan
product:"MongoDB" port:27017 hostname:"example.com"
```

<kbd>Exposed MySQL Databases</kbd>
```shodan
product:"MySQL" port:3306 hostname:"example.com"
```

<kbd>Searching for Open FTP Servers</kbd>
```shodan
port:21 anonymous user:yes hostname:"example.com"
```

<kbd>Open RDP Sessions</kbd>
```shodan
port:3389 has_screenshot:true hostname:"example.com"
```

<kbd>Finding Exposed WordPress Sites</kbd>
```shodan
http.title:"WordPress" OR http.html:"wp-content" hostname:"example.com"
```

<kbd>Unprotected Jenkins Servers</kbd>
```shodan
http.title:"Dashboard [Jenkins]" hostname:"example.com"
```

<kbd>Open SMB Shares</kbd>
```shodan
port:445 os:"Windows" hostname:"example.com"
```

<kbd>Publicly Accessible Cameras</kbd>
```shodan
port:554 has_screenshot:true hostname:"example.com"
```

<kbd>Open Redis Instances</kbd>
```shodan
product:"Redis" port:6379 hostname:"example.com"
```

<kbd>Exposed Git Repositories</kbd>
```shodan
http.html:"/.git" OR http.html:"Index of /.git" hostname:"example.com"
```

<kbd>Publicly Accessible API Endpoints</kbd>
```shodan
http.html:"api" OR http.title:"API" hostname:"example.com"
```

<kbd>Publicly Indexed Log Files</kbd>
```shodan
http.html:"log file" OR http.title:"log" hostname:"example.com"
```

<kbd>Exposed phpMyAdmin Panels</kbd>
```shodan
http.title:"phpMyAdmin" hostname:"example.com"
```

<kbd>Misconfigured AWS S3 Buckets</kbd>
```shodan
http.html:"ListBucketResult" OR http.title:"Index of /" hostname:"example.com"
```

<kbd>Open Kubernetes Dashboards</kbd>
```shodan
http.title:"Kubernetes Dashboard" hostname:"example.com"
```

<kbd>Default Tomcat Manager Login Pages</kbd>
```shodan
http.html:"Tomcat Manager Application" OR http.title:"Apache Tomcat" hostname:"example.com"
```

<kbd>Vulnerable VPN Gateways</kbd>
```shodan
http.title:"Pulse Secure" OR http.title:"Fortinet SSL VPN" hostname:"example.com"
```

<kbd>Identifying Exposed Docker APIs</kbd>
```shodan
product:"Docker" port:2375 hostname:"example.com"
```
