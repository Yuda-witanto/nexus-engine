from http.server import BaseHTTPRequestHandler
import json, os, hashlib, math
from collections import Counter

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')

def calculate_entropy(data):
    if not data: return 0
    freq = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            import shodan
            from supabase import create_client
            
            api = shodan.Shodan(SHODAN_API_KEY)
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            
            queries = ['port:23', 'port:70', 'port:79']
            total = 0
            
            for q in queries:
                try:
                    results = api.search(q, limit=3)
                    for banner in results['matches']:
                        data = banner.get('data', '')
                        ent = calculate_entropy(data)
                        if ent > 3.0:
                            supabase.table('servers').upsert({
                                'ip': banner['ip_str'],
                                'port': banner['port'],
                                'organization': banner.get('org', 'Unknown'),
                                'first_seen': banner.get('timestamp', ''),
                                'last_seen': banner.get('timestamp', ''),
                                'banner_hash': hashlib.sha256(data.encode()).hexdigest()[:16],
                                'entropy': ent,
                                'raw_banner': data
                            }, on_conflict='ip').execute()
                            total += 1
                except Exception as e:
                    print(f"Error: {e}")
            
            supabase.table('expedition_log').insert({
                'action': 'SCAN',
                'details': f'{total} new servers'
            }).execute()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'new_servers': total}).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
