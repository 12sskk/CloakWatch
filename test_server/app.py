from flask import Flask, request
import json
import datetime
import os

app = Flask(__name__)
LOG_FILE = 'test_server_log.jsonl'

def log_request():
    log_data = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers)
    }
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_data) + '\n')

@app.before_request
def before_request():
    log_request()

@app.route('/cloaked')
def cloaked():
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'googlebot' in user_agent or 'bot' in user_agent:
        return '<html><head><title>SEO Content Page</title></head><body><h1>SEO Content Page</h1><p>Buy cheap keywords...</p><a href="#">Cheap links</a></body></html>', 200
    elif 'mobi' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        return '<html><head><title>Mobile Promo</title></head><body><h1>Mobile Promo</h1><p>Welcome to our mobile promo!</p></body></html>', 200
    else:
        return '<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>', 404

@app.route('/responsive')
def responsive():
    content = """<html>
<head>
<title>Responsive Page</title>
<style>
  body { background-color: lightblue; }
  @media (max-width: 600px) {
    body { background-color: lightgreen; }
  }
</style>
</head>
<body>
<h1>Responsive Page</h1>
<p>This is the same content for everyone.</p>
</body>
</html>"""
    return content, 200

@app.route('/static')
def static_page():
    return '<html><head><title>Static Page</title></head><body><h1>Static Page</h1><p>Always the same.</p></body></html>', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port)
