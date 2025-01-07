# Vulnerable Flask Web Application Example

from flask import Flask, request, jsonify
import os
import subprocess
import requests
from datetime import datetime

app = Flask(__name__)

# Dead code (never called)
def dead_code_function():
    print("This function is never used.")

# Unused code (imported but not used)
import hashlib

# Duplicate code
def duplicate_function():
    print("This is a duplicate function.")

def duplicate_function():
    print("This is a duplicate function.")

# Hardcoded secrets (API key and password)
API_KEY = "12345-ABCDE-SECRET-KEY"
DB_PASSWORD = "admin123"

# Vulnerable infrastructure (command injection)
@app.route('/execute', methods=['GET'])
def execute_command():
    command = request.args.get('cmd')
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})

# Outdated library usage (requests library is outdated)
@app.route('/fetch', methods=['GET'])
def fetch_data():
    url = request.args.get('url')
    response = requests.get(url)
    return jsonify({"data": response.text})

# SQL Injection vulnerability
@app.route('/search', methods=['GET'])
def search_user():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Simulate database query execution
    return jsonify({"query": query})

# Hardcoded credentials in infrastructure
AWS_ACCESS_KEY = "AKIAXXXXXXXXXXXXXXXX"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Outdated package (Flask version is outdated)
# Flask 1.1.2 is used here, which has known vulnerabilities

if __name__ == '__main__':
    app.run(debug=True)
