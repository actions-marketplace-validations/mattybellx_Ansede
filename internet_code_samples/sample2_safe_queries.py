import sqlite3
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/user')
def user_data():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Parameterized, should be safe
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return jsonify(cursor.fetchone())
