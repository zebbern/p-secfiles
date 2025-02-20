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

### Finding Exposed Admin Panels
```shodan
http.title:"admin" OR http.title:"login" OR http.html:"admin" hostname:"example.com"
```

### Detecting Open Elasticsearch Instances
```shodan
product:"ElasticSearch" port:9200 hostname:"example.com"
```

### Exposed Databases (MongoDB)
```shodan
product:"MongoDB" port:27017 hostname:"example.com"
```

### Exposed MySQL Databases
```shodan
product:"MySQL" port:3306 hostname:"example.com"
```

### Searching for Open FTP Servers
```shodan
port:21 anonymous user:yes hostname:"example.com"
```

### Open RDP Sessions
```shodan
port:3389 has_screenshot:true hostname:"example.com"
```

### Finding Exposed WordPress Sites
```shodan
http.title:"WordPress" OR http.html:"wp-content" hostname:"example.com"
```

### Unprotected Jenkins Servers
```shodan
http.title:"Dashboard [Jenkins]" hostname:"example.com"
```

### Open SMB Shares
```shodan
port:445 os:"Windows" hostname:"example.com"
```

### Publicly Accessible Cameras
```shodan
port:554 has_screenshot:true hostname:"example.com"
```

### Open Redis Instances
```shodan
product:"Redis" port:6379 hostname:"example.com"
```

### Exposed Git Repositories
```shodan
http.html:"/.git" OR http.html:"Index of /.git" hostname:"example.com"
```

### Publicly Accessible API Endpoints
```shodan
http.html:"api" OR http.title:"API" hostname:"example.com"
```

### Publicly Indexed Log Files
```shodan
http.html:"log file" OR http.title:"log" hostname:"example.com"
```

### Exposed phpMyAdmin Panels
```shodan
http.title:"phpMyAdmin" hostname:"example.com"
```

### Misconfigured AWS S3 Buckets
```shodan
http.html:"ListBucketResult" OR http.title:"Index of /" hostname:"example.com"
```

### Open Kubernetes Dashboards
```shodan
http.title:"Kubernetes Dashboard" hostname:"example.com"
```

### Default Tomcat Manager Login Pages
```shodan
http.html:"Tomcat Manager Application" OR http.title:"Apache Tomcat" hostname:"example.com"
```

### Vulnerable VPN Gateways
```shodan
http.title:"Pulse Secure" OR http.title:"Fortinet SSL VPN" hostname:"example.com"
```

### Identifying Exposed Docker APIs
```shodan
product:"Docker" port:2375 hostname:"example.com"
```
