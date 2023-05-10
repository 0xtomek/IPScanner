# Flask IPScanner
IPscanner in flask : as an input requires POST with json (body) ex.

    { "id"   : "60783958-d6d2-460f-9698-2c419d603b12",
      "ip" : "192.168.1.1"
    }

id (UUID):  identificator of the scan (can be alertId in case integration with Sycope)
ip (IP):    ip of a target

Results are returned and saved to sqlite database.

## Endpoints available

###Scanning endpoints
Port scan
Execute : "nmap -oX - -p 22-443 -sV $IP"
[POST] /port_scan

OS detect
Execute: "nmap -O $IP"
[POST] /os_detect App requires sudo


###Application Endpoints:

Previous scans
List of previously done scans
[GET] /scanlist

Healthcheck
Fixed return 'We will scan the IP provided in Json POST'
[GET] /healthcheck

DB init
Database init outcome
[GET] /init_db
