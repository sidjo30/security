from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

# Vulnerable to SQL Injection
def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    conn.close()
    return user

# Vulnerable to XSS
def get_user_input(user_input):
    return f"<h1>User Input: {user_input}</h1>"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user', methods=['GET'])
def get_user():
    user_id = request.args.get('id')
    user = get_user_by_id(user_id)
    return render_template('user.html', user=user)

@app.route('/submit_input', methods=['POST'])
def submit_input():
    user_input = request.form['input']
    return get_user_input(user_input)

if __name__ == '__main__':
    app.run(debug=True)
