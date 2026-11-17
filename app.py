import os
from flask import Flask, render_template_string, request, session, redirect, url_for
import requests

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "vulnexa_dev_key")
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
        .container { background-color: #2b2b40; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); display: inline-block; width: 900px; }
        input[type="text"] { width: 80%; padding: 10px; border-radius: 5px; border: none; margin-bottom: 20px; }
        button { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #45a049; }
        .result-box { margin-top: 30px; text-align: left; background: #1e1e2f; padding: 20px; border-radius: 5px; border-left: 5px solid #ff4d4d; }
        .logout-btn { background-color: #ff4d4d; margin-top: 20px; font-size: 12px; padding: 5px 10px;}
        
        /* Table Styles */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; border: 1px solid #444; text-align: left; font-size: 14px; }
        th { background-color: #2c3e50; color: white; }
        .Critical { background-color: #ff4d4d; color: white; font-weight: bold; text-align: center; }
        .High { background-color: #ff944d; color: white; font-weight: bold; text-align: center; }
        .Medium { background-color: #ffd633; color: black; font-weight: bold; text-align: center; }
        .Low { background-color: #80ff80; color: black; font-weight: bold; text-align: center; }
        
        code { background-color: #111; color: #00ff00; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VULNEXA Scanner</h1>
        <p>Welcome, Admin. Enter an authorized target URL.</p>
       
        {% if result %}
            <div class="result-box">
                <h3>Scan Report for: {{ target }}</h3>
                <p style="color: #ff4d4d; font-weight: bold;">🔴 {{ result }}</p>
                <form method="POST" id="scanForm">
                   <input type="text" name="url" placeholder="https://example.com" required>
                   <button type="submit" id="scanBtn">Start Scan</button>
                </form>
                {% if vulnerabilities %}
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Impact / Description</th>
                        <th>Solution (Remediation)</th>
                    </tr>
                    {% for v in vulnerabilities %}
                    <tr>
                        <td>{{ v.id }}</td>
                        <td><strong>{{ v.name }}</strong></td>
                        <td class="{{ v.severity }}">{{ v.severity }}</td>
                        <td>{{ v.description }}</td>
                        <td><code>{{ v.remediation }}</code></td>
                    </tr>
                    {% endfor %}
                </table>
                {% endif %}
            </div>
        {% endif %}
        <br><br>
        <a href="/logout"><button class="logout-btn">Logout</button></a>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', function() {
            var btn = document.getElementById('scanBtn');
            btn.innerHTML = "⏳ Scanning..."; 
            btn.style.backgroundColor = "#ffd633"; 
            btn.style.color = "black";
            btn.disabled = true; 
        });
    </script>
</body>
</html>
"""

# --- 3. ROUTING LOGIC ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['password'] == VULNEXA_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            error = "❌ Incorrect Password. Access Denied."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/', methods=['GET', 'POST'])
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    result = None
    target = None
    
    if request.method == 'POST':
        target = request.form['url']
        
        # Ensure HTTPS is used for the scan to work on Render
        if not target.startswith('http'):
            target = 'https://' + target
        elif target.startswith('http://'):
            target = target.replace('http://', 'https://')

        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            
            missing = []
            vulnerabilities_data = []
            
            # The Database of Reports and Solutions
            required_headers = {
                'X-Frame-Options': {
                    'desc': 'Missing protection against Clickjacking. Hackers can embed your site in an invisible frame to trick users into clicking malicious buttons.',
                    'fix': 'X-Frame-Options: DENY'
                },
                'X-XSS-Protection': {
                    'desc': 'Browser Cross-Site Scripting (XSS) filtering is disabled. Malicious scripts can be injected into the page.',
                    'fix': 'X-XSS-Protection: 1; mode=block'
                },
                'Strict-Transport-Security': {
                    'desc': 'HSTS is missing. The browser is not forced to use HTTPS, leaving users vulnerable to Man-in-the-Middle attacks on public Wi-Fi.',
                    'fix': 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
                }
            }
            
            for header, info in required_headers.items():
                if header not in headers:
                    missing.append(header)
                    vulnerabilities_data.append({
                        'id': f'VULN-{len(vulnerabilities_data)+1:03d}',
                        'name': header,
                        'severity': 'Medium',
                        'description': info['desc'],
                        'remediation': info['fix']
                    })
                    
            if missing:
                result = f"Vulnerability Found: {len(missing)} Missing Security Headers (Severity: Medium)."
            else:
                result = "🟢 No missing basic security headers found."
                
            return render_template_string(HTML_TEMPLATE, result=result, target=target, vulnerabilities=vulnerabilities_data)
                
        except Exception as e:
            result = f"Error connecting to target: {e}"
            return render_template_string(HTML_TEMPLATE, result=result, target=target)

    return render_template_string(HTML_TEMPLATE, result=result, target=target)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
