
import nmap
import sqlite3
import json
from flask import Flask, request, render_template, jsonify
from werkzeug.exceptions import abort, HTTPException

app = Flask(__name__)

# -------------------------------OS------------------------------------
# Scanner definition

scanner = nmap.PortScanner()

# --------------------------------DB-----------------------------------
# DB connection

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Get single scan
def get_scan(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE alertId = ?',
                        (scan_id,)).fetchone()
    conn.close()
    if scan is None:
        abort(404)
    return scan

# Update scan db

def update(alertId, targetIp, scanType,  output):

            conn = get_db_connection()
            conn.execute('INSERT INTO scans (alertId, targetIp, scanType, content) VALUES (?, ?, ?, ?)',
                         (alertId, targetIp, scanType, output))
            conn.commit()
            conn.close()

# ---------------------------------WEB APP----------------------------------
# Web Application definition

# Index
@app.route('/')
def base():
    return render_template('index.html')

# Init db
@app.route('/init_db')
def init_db():
    try :
        with app.app_context():
            connection = sqlite3.connect('database.db')
        with open('schema.sql') as f:
            connection.executescript(f.read())

        connection.commit()
        connection.close()
    except : return 'Init failed'
    return 'Init successful'

# Healthcheck
@app.route('/healthcheck')
def healthcheck():
    return 'We will scan the IP provided in Json POST'

# All scans list
@app.route('/scanlist')
def scanlist():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans').fetchall()
    conn.close()
    return render_template('scanslist.html', scans=scans)

# Single scan output
@app.route('/<string:scan_id>')
def scan(scan_id):
    scan = get_scan(scan_id)
    output_json = json.loads(scan[5])
    return output_json

# Right click with scan save to db (port scan)
@app.route('/port_scan', methods=['POST'])
def port_scan():
    content_type = request.headers.get('Content-Type')
    scanType='Port Scan'
    if (content_type == 'application/json'):
        try :
            ip = str(request.json["ip"])
            id = str(request.json["id"])
        except:
            return 'Missing required parameters in Post request. In json mandatory are "id" as alertID and "ip" as target scanned IP'
        scan_output = scanner.scan(ip, '22-443')
        scan_output_to_string = json.dumps(scan_output)
        update(id, ip, scanType,  scan_output_to_string)
        return scan_output
    else:
        return 'Content-Type not supported!'

# Right click with scan save to db (os scan - requires sudo to work)
@app.route('/os_detect', methods=['POST'])
def os_detect():
    content_type = request.headers.get('Content-Type')
    scanType='OS Scan'
    if (content_type == 'application/json'):
        
        try :
            ip = str(request.json["ip"])
            id = str(request.json["id"])
        except:
            return 'Missing required parameters in Post request. In json mandatory are "id" as alertID and "ip" as target scanned IP'
        scan_output = scanner.scan(ip, arguments='-O')
        scan_output_to_string = json.dumps(scan_output)
        update(id, ip, scanType,  scan_output_to_string)
        return scan_output

    else:
        return 'Content-Type not supported!'


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response
