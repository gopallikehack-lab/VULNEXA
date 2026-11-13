import requests

def check_headers(url):
    print(f"Scanning {url} for security headers...\n")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        missing = []
        # List of important security headers
        required_headers = {
            'X-Frame-Options': 'Prevents Clickjacking attacks',
            'X-XSS-Protection': 'Enables browser XSS filtering',
            'Strict-Transport-Security': 'Forces HTTPS connections',
            'Content-Security-Policy': 'Mitigates XSS and data injection'
        }
        
        for header, description in required_headers.items():
            if header not in headers:
                missing.append((header, description))
                
        if missing:
            print("🔴 Vulnerability Found: Missing Security Headers (Severity: Medium)")
            for m in missing:
                print(f"   - Missing: {m[0]} ({m[1]})")
        else:
            print("🟢 No missing basic security headers found.")
            
    except Exception as e:
        print(f"Error scanning: {e}")

# Use a safe, intentionally vulnerable testing site
target = input("Enter target URL (Try: http://testphp.vulnweb.com): ")
check_headers(target)