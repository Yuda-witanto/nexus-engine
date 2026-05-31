import json, os

def handler(request, response):
    path = request.get('path', '/')
    
    if '/api/scan' in path:
        result = {'action': 'scan', 'status': 'running'}
    elif '/api/derive' in path:
        result = {'action': 'derive', 'status': 'running'}
    elif '/api/check' in path:
        result = {'action': 'check', 'status': 'running'}
    else:
        result = {'name': 'Nexus Engine', 'status': 'online', 'version': '3.0'}
    
    return response.status(200).json(result)