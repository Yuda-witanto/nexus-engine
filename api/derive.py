from http.server import BaseHTTPRequestHandler
import json, os, hashlib, hmac

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            from supabase import create_client
            from Crypto.Hash import RIPEMD
            import ecdsa, base58
            
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            servers = supabase.table('servers').select('id,raw_banner').execute()
            
            nonces = [0x04,0x0b,0x0e,0x1a,0x20,0x23,0x2b,0x2c,0x34,0x36]
            methods = ['sha256_concat','hmac_sha512','pbkdf2','double_sha256']
            total = 0
            
            for s in servers.data:
                banner = s.get('raw_banner', '')
                if not banner: continue
                
                for method in methods:
                    for nonce in nonces:
                        data = banner.encode() + nonce.to_bytes(4, 'big')
                        if method == 'sha256_concat':
                            pk = hashlib.sha256(data).digest()
                        elif method == 'hmac_sha512':
                            pk = hmac.new(nonce.to_bytes(4,'big'), banner.encode(), hashlib.sha512).digest()[:32]
                        elif method == 'pbkdf2':
                            pk = hashlib.pbkdf2_hmac('sha512', banner.encode(), nonce.to_bytes(4,'big'), 2048, dklen=32)
                        elif method == 'double_sha256':
                            pk = hashlib.sha256(hashlib.sha256(data).digest()).digest()
                        else:
                            continue
                        
                        sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
                        vk = sk.get_verifying_key()
                        pub = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
                        sha = hashlib.sha256(pub).digest()
                        ripe = RIPEMD.new(sha).digest()
                        raw = b'\x00' + ripe
                        chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
                        addr = base58.b58encode(raw + chk).decode()
                        
                        supabase.table('generated_keys').upsert({
                            'server_id': s['id'],
                            'address': addr,
                            'private_key_hex': pk.hex(),
                            'derivation_method': method,
                            'nonce': nonce
                        }, on_conflict='address').execute()
                        total += 1
            
            supabase.table('expedition_log').insert({
                'action': 'DERIVE',
                'details': f'{total} keys'
            }).execute()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'keys_derived': total}).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
