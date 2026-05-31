from http.server import BaseHTTPRequestHandler
import json, os, requests, time

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            from supabase import create_client
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            
            keys = supabase.table('generated_keys').select('id,server_id,address').eq('balance_btc', 0).limit(10).execute()
            found = 0
            
            for key in keys.data:
                try:
                    resp = requests.get(f"https://blockchain.info/balance?active={key['address']}")
                    if resp.status_code == 200:
                        data = resp.json()
                        bal = data[key['address']]['final_balance'] / 1e8
                        supabase.table('generated_keys').update({
                            'balance_btc': bal
                        }).eq('id', key['id']).execute()
                        
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
                'action': 'CHECK',
                'details': f'{found} anomalies'
            }).execute()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'anomalies_found': found}).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
