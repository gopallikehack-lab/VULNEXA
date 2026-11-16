import os
from flask import Flask, render_template_string, request, session, redirect, url_for
import requests

app = Flask(__name__)

# The secret key secures your login session
app.secret_key = os.environ.get("SECRET_KEY", "vulnexa_dev_key")
# This pulls your secret password from Render's environment variables
VULNEXA_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123") 

# --- 1. THE LOGIN SCREEN ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>VULNEXA - Secure Login</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #1e1e2f; color: white; text-align: center; padding-top: 100px; }
        .container { background-color: #2b2b40; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); display: inline-block; width: 350px; }
        input[type="password"] { width: 80%; padding: 10px; border-radius: 5px; border: none; margin-bottom: 20px; }
        button { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; width: 85%; }
        button:hover { background-color: #45a049; }
        .error { color: #ff4d4d; margin-top: 15px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 VULNEXA Secure Login</h2>
        <p>Enter Owner Password to Access</p>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter Password" required>
            <button type="submit">Unlock Scanner</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

# --- 2. THE MAIN SCANNER PAGE ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>VULNEXA - Web Interface</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #1e1e2f; color: white; text-align: center; padding-top: 50px; }
        .container { background-color: #2b2b40; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); display: inline-block; width: 500px; }
        input[type="text"] { width: 80%; padding: 10px; border-radius: 5px; border: none; margin-bottom: 20px; }
        button { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #45a049; }
        .result-box { margin-top: 30px; text-align: left; background: #1e1e2f; padding: 20px; border-radius: 5px; border-left: 5px solid #ff4d4d; }
        .logout-btn { background-color: #ff4d4d; margin-top: 20px; font-size: 12px; padding: 5px 10px;}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VULNEXA Scanner</h1>
        <p>Welcome, Admin. Enter an authorized target URL.</p>
        
        <form method="POST">
            <input type="text" name="url" placeholder="https://example.com" required>
            <button type="submit">Start Scan</button>
        </form>

        {% if result %}
            <div class="result-box">
                <h3>Scan Results for: {{ target }}</h3>
                <p style="color: #ff4d4d; font-weight: bold;">🔴 {{ result }}</p>
            </div>
        {% endif %}
        
        <br><br>
        <a href="/logout"><button class="logout-btn">Logout</button></a>
    </div>
</body>
</html>
"""

# --- 3. ROUTING LOGIC ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Checks if the password you typed matches the secret one
        if request.form['password'] == VULNEXA_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            error = "❌ Incorrect Password. Access Denied."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/', methods=['GET', 'POST'])
def home():
    # THIS IS THE MAGIC LINE: If you are not logged in, it forces you to the login page!
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    result = None
    target = None
    
    if request.method == 'POST':
        target = request.form['url']
        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            
            missing = []
            required_headers = {
                'X-Frame-Options': 'Prevents Clickjacking',
                'X-XSS-Protection': 'Enables browser XSS filtering',
                'Strict-Transport-Security': 'Forces HTTPS connections'
            }
            
            for header, description in required_headers.items():
                if header not in headers:
                    missing.append(f"{header} ({description})")
                    
            if missing:
                result = "Vulnerability Found: Missing Security Headers (Severity: Medium). Details: "
                result += " | ".join([f"Missing {m}" for m in missing])
            else:
                result = "🟢 No missing basic security headers found."
                
        except Exception as e:
            result = f"Error connecting to target: {e}"

    return render_template_string(HTML_TEMPLATE, result=result, target=target)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
