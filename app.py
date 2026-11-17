import os
from flask import Flask, render_template_string, request, session, redirect, url_for
import requests
import datetime

app = Flask(__name__)

# --- SECURITY & SESSION CONFIGURATION ---
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
        input[type="password"] { width: 80%; padding: 12px; border-radius: 5px; border: none; margin-bottom: 20px; background-color: #1e1e2f; color: white; }
        input[type="password"]:focus { outline: none; box-shadow: 0 0 10px #4CAF50; }
        button { background-color: #4CAF50; color: white; padding: 12px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; width: 85%; transition: all 0.3s ease; }
        button:hover { background-color: #45a049; transform: translateY(-2px); box-shadow: 0 4px 10px rgba(76, 175, 80, 0.4); }
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
        body { font-family: 'Segoe UI', sans-serif; background-color: #1e1e2f; color: white; text-align: center; padding-top: 50px; margin: 0; padding-bottom: 50px;}
        .container { background-color: #2b2b40; padding: 40px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); display: inline-block; width: 900px; }
        
        /* Input & Button Styles */
        input[type="text"] { width: 75%; padding: 12px; border-radius: 5px; border: none; margin-bottom: 20px; background-color: #f4f7f6; color: #333; font-size: 16px; }
        input[type="text"]:focus { outline: none; box-shadow: 0 0 10px #4CAF50; }
        button { background-color: #4CAF50; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; transition: all 0.3s ease; }
        button:hover { background-color: #45a049; transform: translateY(-2px); box-shadow: 0 4px 10px rgba(76, 175, 80, 0.4); }
        
        /* Result Box & Animation */
        .result-box { margin-top: 30px; text-align: left; background: #1e1e2f; padding: 25px; border-radius: 5px; border-left: 5px solid #ff4d4d; animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(255, 77, 77, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(255, 77, 77, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 77, 77, 0); }
        }
        
        /* Table Styles */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 15px; border: 1px solid #444; text-align: left; font-size: 14px; vertical-align: top;}
        th { background-color: #2c3e50; color: white; font-weight: 600; }
        .Critical { background-color: #ff4d4d; color: white; font-weight: bold; text-align: center; }
        .High { background-color: #ff944d; color: white; font-weight: bold; text-align: center; }
        .Medium { background-color: #ffd633; color: black; font-weight: bold; text-align: center; }
        .Low { background-color: #80ff80; color: black; font-weight: bold; text-align: center; }
        
        /* Code Snippet Style */
        code { background-color: #111; color: #00ff00; padding: 5px 8px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; display: inline-block; word-break: break-all; }
        
        .logout-btn { background-color: #ff4d4d; margin-top: 30px; font-size: 14px; padding: 8px 15px; }
        .logout-btn:hover { background-color: #cc0000; box-shadow: 0 4px 10px rgba(255, 77, 77, 0.4); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VULNEXA Scanner</h1>
        <p>Welcome, Admin. Enter an authorized target URL.</p>
        
        <!-- Form with IDs for JavaScript -->
        <form method="POST" id="scanForm">
            <input type="text" name="url" placeholder="https://example.com" required>
            <button type="submit" id="scanBtn">Start Scan</button>
        </form>

        {% if result %}
            <div class="result-box">
                <div style="border-bottom: 2px solid #444; padding-bottom: 10px; margin-bottom: 20px;">
                    <h3 style="margin: 0; color: #4CAF50;">🎯 Target: <span style="color: white;">{{ target }}</span></h3>
                    <p style="font-size: 12px; color: #999; margin-top: 5px;">Status: Preliminary Findings (Requires Verification)</p>
                </div>
                
                <p style="color: #ff4d4d; font-weight: bold; font-size: 18px;">⚠️ {{ result }}</p>
                
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
                        <td><strong>{{ v.id }}</strong></td>
                        <td>{{ v.name }}</td>
                        <td class="{{ v.severity }}">{{ v.severity }}</td>
                        <td>{{ v.description }}</td>
                        <td><code>{{ v.remediation }}</code></td>
                    </tr>
                    {% endfor %}
                </table>
                {% endif %}
            </div>
        {% endif %}
        
        <br>
        <a href="/logout"><button class="logout-btn">Logout</button></a>
    </div>

    <!-- JavaScript for the Loading Button -->
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
    # Protection: If not logged in, go to login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    result = None
    target = None
    
    if request.method == 'POST':
        target = request.form['url']
        
        # Force HTTPS
        if not target.startswith('http'):
            target = 'https://' + target
        elif target.startswith('http://'):
            target = target.replace('http://', 'https://')

        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            
            missing = []
            vulnerabilities_data = []
            
            # Database of Reports and Solutions
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
    # Clear the session completely
    session.clear() 
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
