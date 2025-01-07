from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Hardcoded secret key (vulnerability)

# Database setup
def init_db():
    """Initializes the database with necessary tables.
    Parameters:
        None
    Returns:
        None
    Processing Logic:
        - Connects to an SQLite database named 'vulnerable_app.db'.
        - Creates 'users' and 'posts' tables if they do not already exist.
        - Commits the changes and closes the connection."""
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS posts (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        content TEXT
                    )''')
    conn.commit()
    conn.close()

# Insecure password hashing (MD5 is weak)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerable to SQL Injection
def get_user_by_username(username):
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username='{username}'")
    user = cursor.fetchone()
    conn.close()
    return user

# Vulnerable to IDOR
def get_post_by_id(post_id):
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM posts WHERE id={post_id}")
    post = cursor.fetchone()
    conn.close()
    return post

# Vulnerable to XSS
def render_post(post_content):
    return f"<div>{post_content}</div>"

@app.route('/')
def index():
    if 'username' in session:
        return f"Welcome, {session['username']}! <a href='/logout'>Logout</a>"
    return "Welcome! <a href='/login'>Login</a> or <a href='/register'>Register</a>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers a user into the application.
    Parameters:
        - None
    Returns:
        - Response object: A redirect to the 'login' route if the request method is POST. 
        - HTML Template: Renders the 'register.html' template for GET requests.
    Processing Logic:
        - Hashes the password before storing it in the database.
        - Inserts user credentials into the 'users' table.
        - Redirects to the login page after successful registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed_password}')")
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate a user and establish a session if credentials are valid.
    Parameters:
        - None
    Returns:
        - str or object: A redirection to the 'index' page if login is successful, an "Invalid credentials" message if unsuccessful, or the login form if the request method is not POST.
    Processing Logic:
        - Verifies user credentials by checking hashed passwords.
        - Initiates a session with username and user ID upon successful login. 
        - Returns login form for GET requests."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        if user and user[2] == hash_password(password):
            session['username'] = username
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/posts/<int:post_id>')
def view_post(post_id):
    post = get_post_by_id(post_id)
    if post:
        return render_post(post[2])
    return "Post not found"

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    """Creates a new post in the application if the user is logged in.
    Parameters:
        - None
    Returns:
        - redirect: Redirects the user to login page if they are not logged in, or to the index page after creating a post.
        - render_template: Renders the 'create_post.html' page if the request method is not POST.
    Processing Logic:
        - Checks session for 'username' to verify user login.
        - Establishes a connection to the SQLite database to insert a new post entry.
        - Uses user session information to create a post associated with the logged-in user."""
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        user_id = session['user_id']
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO posts (user_id, content) VALUES ({user_id}, '{content}')")
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('create_post.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
