from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        routes = {
            '/': 'Nexus Engine Dashboard',
            '/api/scan': 'Trigger Shodan scan',
            '/api/derive': 'Derive keys from servers',
            '/api/check': 'Check blockchain balances'
        }
        
        self.wfile.write(json.dumps({
            'name': '🧬 Nexus Engine',
            'version': '2.0',
            'status': 'running',
            'endpoints': routes
        }).encode())
