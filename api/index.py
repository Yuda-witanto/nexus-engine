from http.server import BaseHTTPRequestHandler
<<<<<<< HEAD
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
        
=======
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
>>>>>>> fbdc168e92be7e6a2267a7fc66ae0803e4dad6f5
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
<<<<<<< HEAD
        self.wfile.write(json.dumps(result).encode())
=======
        
        # DEBUG: Lihat path apa yang diterima
        result = {
            'path': self.path,
            'headers': dict(self.headers),
            'message': 'Debug info'
        }
        
        self.wfile.write(json.dumps(result).encode())
>>>>>>> fbdc168e92be7e6a2267a7fc66ae0803e4dad6f5
