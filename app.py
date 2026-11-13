from flask import Flask, render_template_string, request
import requests

app = Flask(__name__)

# --- HTML TEMPLATE (Frontend UI) ---
# This makes the website look nice and modern without needing separate HTML files
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VULNEXA Scanner</h1>
        <p>Enter an authorized target URL to scan for vulnerabilities</p>
        
        <form method="POST">
            <input type="text" name="url" placeholder="http://neverssl.com" required>
            <button type="submit">Start Scan</button>
        </form>

        {% if result %}
            <div class="result-box">
                <h3>Scan Results for: {{ target }}</h3>
                <p style="color: #ff4d4d; font-weight: bold;">🔴 {{ result }}</p>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    target = None
    
    if request.method == 'POST':
        target = request.form['url']
        try:
            # Live scanning logic
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
                result = "Vulnerability Found: Missing Security Headers (Severity: Medium)<br><br>"
                result += "<br>".join([f" - Missing: {m}" for m in missing])
            else:
                result = "🟢 No missing basic security headers found."
                
        except Exception as e:
            result = f"Error connecting to target: {e}"

    return render_template_string(HTML_TEMPLATE, result=result, target=target)

if __name__ == '__main__':
    app.run(debug=True)