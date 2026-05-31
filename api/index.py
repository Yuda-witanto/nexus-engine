from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # DEBUG: Lihat path apa yang diterima
        result = {
            'path': self.path,
            'headers': dict(self.headers),
            'message': 'Debug info'
        }
        
        self.wfile.write(json.dumps(result).encode())
