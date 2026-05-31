from http.server import BaseHTTPRequestHandler
import json, os

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/scan':
            result = {'action': 'scan', 'status': 'running'}
        elif self.path == '/api/derive':
            result = {'action': 'derive', 'status': 'running'}
        elif self.path == '/api/check':
            result = {'action': 'check', 'status': 'running'}
        else:
            result = {'name': 'Nexus Engine', 'status': 'online', 'version': '2.0'}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())