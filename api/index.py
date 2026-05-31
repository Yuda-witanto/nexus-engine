from http.server import BaseHTTPRequestHandler
import json, os, hashlib, math, hmac, requests, time
from collections import Counter

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if '/api/scan' in self.path:
                result = self.scan()
            elif '/api/derive' in self.path:
                result = self.derive()
            elif '/api/check' in self.path:
                result = self.check()
            else:
                result = {'name': 'Nexus Engine', 'status': 'online', 'version': '2.0'}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
    
    def scan(self):
        SHODAN_KEY = os.environ.get('SHODAN_API_KEY', '')
        SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
        SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
        
        if not SHODAN_KEY:
            return {'error': 'Environment variables not set'}
        
        import shodan
        from supabase import create_client
        
        api = shodan.Shodan(SHODAN_KEY)
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        total = 0
        for q in ['port:23', 'port:70', 'port:79']:
            try:
                for b in api.search(q, limit=3)['matches']:
                    d = b.get('data', '')
                    if d:
                        freq = Counter(d)
                        ent = -sum((c/len(d)) * math.log2(c/len(d)) for c in freq.values())
                        if ent > 3.0:
                            try:
                                supabase.table('servers').upsert({
                                    'ip': b['ip_str'], 'port': b['port'],
                                    'organization': b.get('org', 'Unknown'),
                                    'entropy': ent, 'raw_banner': d
                                }, on_conflict='ip').execute()
                                total += 1
                            except: pass
            except: pass
        
        supabase.table('expedition_log').insert({'action': 'SCAN', 'details': f'{total} servers'}).execute()
        return {'success': True, 'new_servers': total}
    
    def derive(self):
        SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
        SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
        
        from supabase import create_client
        from Crypto.Hash import RIPEMD
        import ecdsa, base58
        
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        servers = supabase.table('servers').select('id,raw_banner').execute()
        
        nonces = [0x04,0x0b,0x0e,0x1a,0x20]
        methods = ['sha256_concat','hmac_sha512']
        total = 0
        
        for s in servers.data:
            banner = s.get('raw_banner', '')
            if not banner: continue
            for method in methods:
                for nonce in nonces:
                    data = banner.encode() + nonce.to_bytes(4, 'big')
                    if method == 'sha256_concat':
                        pk = hashlib.sha256(data).digest()
                    else:
                        pk = hmac.new(nonce.to_bytes(4,'big'), banner.encode(), hashlib.sha512).digest()[:32]
                    
                    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
                    vk = sk.get_verifying_key()
                    pub = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
                    sha = hashlib.sha256(pub).digest()
                    ripe = RIPEMD.new(sha).digest()
                    raw = b'\x00' + ripe
                    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
                    addr = base58.b58encode(raw + chk).decode()
                    
                    try:
                        supabase.table('generated_keys').upsert({
                            'server_id': s['id'], 'address': addr,
                            'private_key_hex': pk.hex(), 'derivation_method': method,
                            'nonce': nonce
                        }, on_conflict='address').execute()
                        total += 1
                    except: pass
        
        supabase.table('expedition_log').insert({'action': 'DERIVE', 'details': f'{total} keys'}).execute()
        return {'success': True, 'keys_derived': total}
    
    def check(self):
        SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
        SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
        
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        keys = supabase.table('generated_keys').select('id,server_id,address').eq('balance_btc', 0).limit(5).execute()
        found = 0
        
        for key in keys.data:
            try:
                r = requests.get(f"https://blockchain.info/balance?active={key['address']}")
                if r.status_code == 200:
                    bal = r.json()[key['address']]['final_balance'] / 1e8
                    supabase.table('generated_keys').update({'balance_btc': bal}).eq('id', key['id']).execute()
                    if bal > 0:
                        supabase.table('anomalies').insert({
                            'server_id': key['server_id'], 'anomaly_type': 'BALANCE',
                            'description': f"{key['address']}: {bal} BTC", 'severity': 'HIGH'
                        }).execute()
                        found += 1
                time.sleep(0.3)
            except: pass
        
        supabase.table('expedition_log').insert({'action': 'CHECK', 'details': f'{found} anomalies'}).execute()
        return {'success': True, 'anomalies_found': found}
