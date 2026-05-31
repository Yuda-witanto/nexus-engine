from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({
            'name': 'Nexus Engine',
            'version': '2.0',
            'status': 'online',
            'endpoints': {
                '/api/scan': 'Scan Shodan for ghost servers',
                '/api/derive': 'Derive cryptographic keys',
                '/api/check': 'Check blockchain balances'
            }
        }).encode())
