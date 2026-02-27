import requests
from modules.xss_detector import XSSDetector

# Step 1: Login to get session
print("Step 1: Logging in...\n")
session = requests.Session()

login_data = {
    'username': 'testuser',
    'password': 'password123'
}

login_response = session.post('http://127.0.0.1:5000/login', data=login_data)

if 'dashboard' in login_response.url or login_response.status_code == 302:
    print("[SUCCESS] Logged in!\n")
else:
    print("[ERROR] Login failed. Make sure testuser account exists.")
    exit()

# Step 2: Manually define the Add Expense form
add_expense_form = {
    'url': 'http://127.0.0.1:5000/add-expense',
    'action': 'http://127.0.0.1:5000/add-expense',
    'method': 'post',
    'inputs': [
        {'type': 'text', 'name': 'description', 'value': ''},
        {'type': 'number', 'name': 'amount', 'value': ''},
        {'type': 'date', 'name': 'date', 'value': ''}
    ]
}

# Step 3: Test for XSS
print("Step 2: Testing Add Expense form for XSS...\n")

# We need to modify the detector to use our session
# For now, let's manually test

payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]

for payload in payloads:
    print(f"[TEST] Trying payload: {payload}")
    
    test_data = {
        'description': payload,
        'amount': '5.00',
        'date': '2026-02-06'
    }
    
    response = session.post('http://127.0.0.1:5000/add-expense', data=test_data)
    
    # Check if redirected to dashboard
    if response.status_code == 302 or 'dashboard' in response.url:
        print("[INFO] Expense added, checking if stored XSS exists...")
        
        # Get the latest expense ID (assume it's the last one)
        # In a real scanner, we'd parse the dashboard to find expense IDs
        
        print(f"{Fore.GREEN}[INFO] Payload stored. Manual verification needed:")
        print(f"       Visit http://127.0.0.1:5000/dashboard")
        print(f"       Click on the expense with description containing the payload")
        print(f"       If alert popup appears = XSS VULNERABLE!")
        break

print("\n[DONE] Manual XSS testing complete.")
print("Note: For full automation, scanner needs session management.")