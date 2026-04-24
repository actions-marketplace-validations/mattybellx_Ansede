import sqlite3
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ' + user_id) # SQLi
    user = cursor.fetchone()
    return render_template_string('<h1>User: ' + request.args.get('name') + '</h1>', user=user) # XSS
