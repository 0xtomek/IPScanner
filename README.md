# Flask IPScanner
IPscanner in flask : as an input requires POST with json (body). In general it requires two variables:

id (UUID):  identificator of the scan (can be alertId in case integration with Sycope)
ip (IP):    ip of a target

ex. json body file attached where id = str(request.json["id"]) and ip = str(request.json["clientIp"]["addressString"])

Results are returned and saved to sqlite database.

## Endpoints available

### Scanning endpoints
Port scan
Execute : "nmap -oX - -p 22-443 -sV $IP"
[POST] /port_scan

OS detect
Execute: "nmap -O $IP"
[POST] /os_detect App requires sudo


### Application Endpoints:

Previous scans
List of previously done scans
[GET] /scanlist

Healthcheck
Fixed return 'We will scan the IP provided in Json POST'
[GET] /healthcheck

DB init
Database init outcome
[GET] /init_db

### Docker

 docker build --tag ipscanner . followed by docker run -p 127.0.0.1:5000:5000 ipscanner
