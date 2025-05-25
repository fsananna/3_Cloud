from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
import bcrypt
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# MySQL configurations
db_config = {
    'host': os.environ.get('MYSQL_HOST'),
    'port': int(os.environ.get('MYSQL_PORT', 3306)),
    'user': os.environ.get('MYSQL_USER'),
    'password': os.environ.get('MYSQL_PASSWORD'),
    'database': os.environ.get('MYSQL_DB'),
    'cursorclass': pymysql.cursors.DictCursor,
    'ssl': {'ca': None, 'check_hostname': False}  # Adjust for Aiven if needed
}

# Debug print
print("MYSQL_HOST:", db_config['host'])
print("MYSQL_PORT:", db_config['port'])
print("MYSQL_USER:", db_config['user'])
print("MYSQL_DB:", db_config['database'])

# Optional: Try resolving DNS (debugging only)
import socket
try:
    ip = socket.gethostbyname(db_config['host'])
    print(f"Resolved IP: {ip}")
except Exception as e:
    print(f"DNS resolution error: {e}")

# Establish connection
import traceback

def get_db_connection():
    try:
        print("Connecting to MySQL with:")
        for key, val in db_config.items():
            if key != 'password':
                print(f"{key}: {val}")
        conn = pymysql.connect(**db_config)
        print("✅ MySQL connection successful")
        return conn
    except Exception as e:
        print("❌ MySQL connection failed:")
        traceback.print_exc()
        return None

@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('profile.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        conn = get_db_connection()
        if conn is None:
            msg = 'Database connection failed!'
            return render_template('login.html', msg=msg)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['loggedin'] = True
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username or password!'
    return render_template('login.html', msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        email = request.form['email']
        conn = get_db_connection()
        if conn is None:
            msg = 'Database connection failed!'
            return render_template('register.html', msg=msg)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        email_check = cursor.fetchone()

        if account:
            msg = 'Username already taken!'
        elif email_check:
            msg = 'Email already in use!'
        elif not re.match(r'^[A-Za-z][A-Za-z0-9_]{4,19}$', username):
            msg = 'Username must start with a letter and be 5–20 characters (letters, numbers, underscore only)!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$', password.decode('utf-8')):
            msg = 'Password must contain uppercase, lowercase, number, and special character!'
        else:
            hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
            cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)', (username, hashed, email))
            conn.commit()
            flash('You have successfully registered!', 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        cursor.close()
        conn.close()
    return render_template('register.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
