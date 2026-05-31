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
@app.route('/api/')
def home():
    return {
        'name': 'Nexus Engine',
        'version': '2.0',
        'status': 'online',
        'endpoints': {
            '/api/scan': 'Scan Shodan for ghost servers',
            '/api/derive': 'Derive cryptographic keys',
            '/api/check': 'Check blockchain balances'
        }
    }

@app.route('/api/scan')
def scan():
    try:
        import shodan
        from supabase import create_client
        
        if not SHODAN_API_KEY:
            return {'error': 'SHODAN_API_KEY not set'}
        
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
                        try:
                            supabase.table('servers').upsert({
                                'ip': banner['ip_str'],
                                'port': banner['port'],
                                'organization': banner.get('org', 'Unknown'),
                                'entropy': ent,
                                'raw_banner': data
                            }, on_conflict='ip').execute()
                            total += 1
                        except: pass
            except: pass
        
        supabase.table('expedition_log').insert({
            'action': 'SCAN', 'details': f'{total} servers'
        }).execute()
        
        return {'success': True, 'new_servers': total}
    except Exception as e:
        return {'error': str(e)}

@app.route('/api/derive')
def derive():
    try:
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
                            'server_id': s['id'],
                            'address': addr,
                            'private_key_hex': pk.hex(),
                            'derivation_method': method,
                            'nonce': nonce
                        }, on_conflict='address').execute()
                        total += 1
                    except: pass
        
        supabase.table('expedition_log').insert({
            'action': 'DERIVE', 'details': f'{total} keys'
        }).execute()
        
        return {'success': True, 'keys_derived': total}
    except Exception as e:
        return {'error': str(e)}

@app.route('/api/check')
def check():
    try:
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
                            'server_id': key['server_id'],
                            'anomaly_type': 'BALANCE',
                            'description': f"{key['address']}: {bal} BTC",
                            'severity': 'HIGH'
                        }).execute()
                        found += 1
                time.sleep(0.3)
            except: pass
        
        supabase.table('expedition_log').insert({
            'action': 'CHECK', 'details': f'{found} anomalies'
        }).execute()
        
        return {'success': True, 'anomalies_found': found}
    except Exception as e:
        return {'error': str(e)}

handler = app