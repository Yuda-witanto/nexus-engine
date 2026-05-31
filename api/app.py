from flask import Flask
import json, os, hashlib, math, hmac, requests, time
from collections import Counter

app = Flask(__name__)

SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')

def calculate_entropy(data):
    if not data: return 0
    freq = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

@app.route('/')
def home():
    return {'name': 'Nexus Engine', 'status': 'online'}

@app.route('/api/scan')
def scan():
    try:
        import shodan
        from supabase import create_client
        if not SHODAN_API_KEY: return {'error': 'ENV not set'}
        api = shodan.Shodan(SHODAN_API_KEY)
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        total = 0
        for q in ['port:23', 'port:70', 'port:79']:
            try:
                for b in api.search(q, limit=3)['matches']:
                    d = b.get('data', '')
                    ent = calculate_entropy(d)
                    if ent > 3.0:
                        supabase.table('servers').upsert({
                            'ip': b['ip_str'], 'port': b['port'],
                            'organization': b.get('org', 'Unknown'),
                            'entropy': ent, 'raw_banner': d
                        }, on_conflict='ip').execute()
                        total += 1
            except: pass
        supabase.table('expedition_log').insert({'action': 'SCAN', 'details': f'{total} servers'}).execute()
        return {'success': True, 'new_servers': total}
    except Exception as e:
        return {'error': str(e)}

@app.route('/api/derive')
def derive():
    return {'action': 'derive', 'status': 'running'}

@app.route('/api/check')
def check():
    return {'action': 'check', 'status': 'running'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
