import os
import sqlite3
import requests
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded Credentials
DB_PASSWORD = "hardcoded_password"
DB_USERNAME = "hardcoded_user"

# Vulnerability 2: SQL Injection
@app.route('/users', methods=['GET'])
def get_users():
    user_input = request.args.get('name')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    return str(results)

# Vulnerability 3: Command Injection
@app.route('/run_command', methods=['GET'])
def run_command():
    command = request.args.get('command')
    os.system(command)
    return "Command executed"

# Vulnerability 4: Cross-Site Scripting (XSS)
@app.route('/xss', methods=['GET'])
def xss_example():
    user_input = request.args.get('input')
    return "<div>" + user_input + "</div>"

# Vulnerability 5: Insecure Deserialization
import pickle

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.get_json()['data']
    try:
        return pickle.loads(data)
    except Exception as e:
        return str(e)

# Vulnerability 6: Outdated Library Usage
import requests

@app.route('/make_request', methods=['GET'])
def make_request():
    response = requests.get("http://example.com", verify=False)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)
