import urllib.request
import requests
from flask import Flask, request
app = Flask(__name__)

@app.route('/fetch_preview')
def fetch_preview():
    url = request.args.get('url')
    if url:
        resp = requests.get(url)  # SSRF vulnerability
        return resp.text
    return 'No url'
