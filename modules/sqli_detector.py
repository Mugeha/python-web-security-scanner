import requests
import time
from colorama import Fore, Style, init

init(autoreset=True)

class SQLiDetector:
    """
    SQL Injection vulnerability detector.
    Tests forms and parameters for SQL injection vulnerabilities.
    """
    
    def __init__(self, payloads_file='payloads/sqli.txt'):
        """
        Initialize the SQL injection detector.
        
        Args:
            payloads_file (str): Path to file containing SQLi payloads
        """
        self.payloads = self.load_payloads(payloads_file)
        self.vulnerabilities = []
        
        # Common SQL error messages to detect
        self.error_patterns = [
            'sql syntax',
            'mysql',
            'sqlite',
            'postgresql',
            'ora-',
            'syntax error',
            'unclosed quotation',
            'quoted string not properly terminated',
            'microsoft sql server',
            'odbc',
            'jdbc',
            'sqlite3.operational',
            'pg_query',
            'mysql_fetch',
            'sqlserver',
            'warning: mysql',
            'valid mysql result',
            'MySqlClient',
            'postgres',
            'SQL command not properly ended',
            'unterminated quoted string',
        ]
    
    def load_payloads(self, filename):
        """
        Load SQL injection payloads from file.
        
        Args:
            filename (str): Path to payloads file
            
        Returns:
            list: List of payload strings
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[LOADED] {len(payloads)} SQL injection payloads")
            return payloads
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Payloads file not found: {filename}")
            return []
    
    def has_sql_error(self, response_text):
        """
        Check if response contains SQL error messages.
        
        Args:
            response_text (str): HTTP response body
            
        Returns:
            tuple: (bool, str) - (has_error, matching_pattern)
        """
        response_lower = response_text.lower()
        
        for pattern in self.error_patterns:
            if pattern in response_lower:
                return True, pattern
        
        return False, None
    
    def test_form(self, form_details):
        """
        Test a form for SQL injection vulnerabilities.
        
        Args:
            form_details (dict): Form information from crawler
            
        Returns:
            list: List of vulnerabilities found
        """
        print(f"\n{Fore.CYAN}[TEST] Testing form: {form_details['action']}")
        print(f"{Fore.CYAN}[INFO] Method: {form_details['method'].upper()}")
        print(f"{Fore.CYAN}[INFO] Inputs: {len(form_details['inputs'])}")
        
        form_vulnerabilities = []
        
        # Get baseline response (normal request)
        baseline_data = {}
        for input_field in form_details['inputs']:
            baseline_data[input_field['name']] = 'test'
        
        try:
            if form_details['method'] == 'get':
                baseline_response = requests.get(
                    form_details['action'], 
                    params=baseline_data,
                    timeout=10,
                    allow_redirects=False
                )
            else:  # POST
                baseline_response = requests.post(
                    form_details['action'],
                    data=baseline_data,
                    timeout=10,
                    allow_redirects=False
                )
            
            baseline_content = baseline_response.text
            baseline_length = len(baseline_content)
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] Failed to get baseline: {str(e)}")
            return form_vulnerabilities
        
        # Test each input field with each payload
        for input_field in form_details['inputs']:
            input_name = input_field['name']
            
            # Skip non-text inputs
            if input_field['type'] in ['submit', 'button', 'image', 'reset']:
                continue
            
            print(f"{Fore.YELLOW}[TESTING] Input field: {input_name}")
            
            for payload in self.payloads:
                # Prepare test data
                test_data = baseline_data.copy()
                test_data[input_name] = payload
                
                try:
                    # Send request with payload
                    start_time = time.time()
                    
                    if form_details['method'] == 'get':
                        response = requests.get(
                            form_details['action'],
                            params=test_data,
                            timeout=10,
                            allow_redirects=False
                        )
                    else:  # POST
                        response = requests.post(
                            form_details['action'],
                            data=test_data,
                            timeout=10,
                            allow_redirects=False
                        )
                    
                    response_time = time.time() - start_time
                    response_content = response.text
                    
                    # Detection Method 1: Error-based SQLi
                    has_error, error_pattern = self.has_sql_error(response_content)
                    
                    if has_error:
                        vuln = {
                            'type': 'SQL Injection (Error-based)',
                            'url': form_details['action'],
                            'method': form_details['method'].upper(),
                            'parameter': input_name,
                            'payload': payload,
                            'evidence': error_pattern,
                            'severity': 'CRITICAL'
                        }
                        form_vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[VULN!] SQL Injection found in '{input_name}'")
                        print(f"{Fore.RED}        Payload: {payload}")
                        print(f"{Fore.RED}        Evidence: {error_pattern}")
                        
                        # Stop testing this field once vulnerability confirmed
                        break
                    
                    # Detection Method 2: Boolean-based SQLi
                    # Check for significant response length difference
                    length_diff = abs(len(response_content) - baseline_length)
                    
                    if length_diff > 100:  # Arbitrary threshold
                        # Try to confirm with opposite boolean
                        opposite_payload = payload.replace("'1'='1", "'1'='2").replace('"1"="1', '"1"="2')
                        
                        if opposite_payload != payload:
                            test_data_opposite = baseline_data.copy()
                            test_data_opposite[input_name] = opposite_payload
                            
                            if form_details['method'] == 'get':
                                response_opposite = requests.get(
                                    form_details['action'],
                                    params=test_data_opposite,
                                    timeout=10,
                                    allow_redirects=False
                                )
                            else:
                                response_opposite = requests.post(
                                    form_details['action'],
                                    data=test_data_opposite,
                                    timeout=10,
                                    allow_redirects=False
                                )
                            
                            # If opposite payload gives different response, likely vulnerable
                            if abs(len(response_opposite.text) - len(response_content)) > 50:
                                vuln = {
                                    'type': 'SQL Injection (Boolean-based)',
                                    'url': form_details['action'],
                                    'method': form_details['method'].upper(),
                                    'parameter': input_name,
                                    'payload': payload,
                                    'evidence': f'Response length diff: {length_diff} bytes',
                                    'severity': 'CRITICAL'
                                }
                                form_vulnerabilities.append(vuln)
                                print(f"{Fore.RED}[VULN!] SQL Injection found in '{input_name}'")
                                print(f"{Fore.RED}        Payload: {payload}")
                                print(f"{Fore.RED}        Type: Boolean-based")
                                break
                    
                    # Detection Method 3: Time-based SQLi
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                        if response_time > 4:  # Should delay ~5 seconds
                            vuln = {
                                'type': 'SQL Injection (Time-based)',
                                'url': form_details['action'],
                                'method': form_details['method'].upper(),
                                'parameter': input_name,
                                'payload': payload,
                                'evidence': f'Response delayed by {response_time:.2f} seconds',
                                'severity': 'CRITICAL'
                            }
                            form_vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[VULN!] SQL Injection found in '{input_name}'")
                            print(f"{Fore.RED}        Payload: {payload}")
                            print(f"{Fore.RED}        Type: Time-based")
                            break
                
                except requests.exceptions.Timeout:
                    # Timeout might indicate time-based SQLi
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                        vuln = {
                            'type': 'SQL Injection (Time-based)',
                            'url': form_details['action'],
                            'method': form_details['method'].upper(),
                            'parameter': input_name,
                            'payload': payload,
                            'evidence': 'Request timeout (>10 seconds)',
                            'severity': 'CRITICAL'
                        }
                        form_vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[VULN!] SQL Injection found in '{input_name}'")
                        print(f"{Fore.RED}        Payload: {payload}")
                        print(f"{Fore.RED}        Type: Time-based (timeout)")
                        break
                
                except requests.exceptions.RequestException as e:
                    # Network error, skip this payload
                    continue
        
        return form_vulnerabilities
    
    def scan(self, forms):
        """
        Scan all forms for SQL injection vulnerabilities.
        
        Args:
            forms (list): List of form dictionaries from crawler
            
        Returns:
            list: All vulnerabilities found
        """
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}SQL INJECTION SCAN")
        print(f"{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Testing {len(forms)} forms with {len(self.payloads)} payloads\n")
        
        all_vulnerabilities = []
        
        for form in forms:
            form_vulns = self.test_form(form)
            all_vulnerabilities.extend(form_vulns)
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}SQL INJECTION SCAN COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        
        if all_vulnerabilities:
            print(f"{Fore.RED}[FOUND] {len(all_vulnerabilities)} SQL injection vulnerability(ies)")
        else:
            print(f"{Fore.GREEN}[CLEAN] No SQL injection vulnerabilities found")
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities