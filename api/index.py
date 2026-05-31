from http.server import BaseHTTPRequestHandler
import json, os

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '/api/scan' in self.path:
            result = {'action': 'scan', 'status': 'running'}
        elif '/api/derive' in self.path:
            result = {'action': 'derive', 'status': 'running'}
        elif '/api/check' in self.path:
            result = {'action': 'check', 'status': 'running'}
        else:
            result = {'name': 'Nexus Engine', 'status': 'online', 'version': '3.0'}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())