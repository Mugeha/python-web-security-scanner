import requests
import html
import re
from urllib.parse import quote, unquote
from colorama import Fore, Style, init

init(autoreset=True)

class XSSDetector:
    """
    Cross-Site Scripting (XSS) vulnerability detector.
    Tests forms and parameters for XSS vulnerabilities.
    """
    
    def __init__(self, payloads_file='payloads/xss.txt'):
        """
        Initialize the XSS detector.
        
        Args:
            payloads_file (str): Path to file containing XSS payloads
        """
        self.payloads = self.load_payloads(payloads_file)
        self.vulnerabilities = []
        
        # Unique marker to identify our payloads in responses
        self.marker = "XSS_TEST_MARKER_"
    
    def load_payloads(self, filename):
        """
        Load XSS payloads from file.
        
        Args:
            filename (str): Path to payloads file
            
        Returns:
            list: List of payload strings
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[LOADED] {len(payloads)} XSS payloads")
            return payloads
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Payloads file not found: {filename}")
            return []
    
    def is_reflected(self, payload, response_text):
        """
        Check if payload is reflected in the response.
        
        Args:
            payload (str): The XSS payload
            response_text (str): HTTP response body
            
        Returns:
            tuple: (bool, str) - (is_reflected, context)
        """
        # Check if payload appears in response exactly
        if payload in response_text:
            return True, "exact"
        
        # Check for HTML-encoded version
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True, "html_encoded"
        
        # Check for URL-encoded version
        url_encoded = quote(payload)
        if url_encoded in response_text:
            return True, "url_encoded"
        
        # Check for double-encoded
        double_encoded = quote(quote(payload))
        if double_encoded in response_text:
            return True, "double_encoded"
        
        # Check for partial reflection (without some characters)
        # This catches cases where some filtering is applied
        stripped_payload = re.sub(r'[<>"\'=]', '', payload)
        if len(stripped_payload) > 5 and stripped_payload in response_text:
            return True, "partial"
        
        return False, None
    
    def check_executable(self, payload, response_text):
        """
        Check if the reflected payload would execute (not properly escaped).
        
        Args:
            payload (str): The XSS payload
            response_text (str): HTTP response body
            
        Returns:
            bool: True if likely executable
        """
        # Look for common XSS patterns that would execute
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<img[^>]+onerror\s*=',
            r'<svg[^>]+onload\s*=',
            r'<iframe[^>]+src\s*=\s*["\']?javascript:',
            r'<body[^>]+onload\s*=',
            r'<input[^>]+onfocus\s*=',
            r'javascript:\s*alert',
            r'on\w+\s*=\s*["\']?alert',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check if script tags are intact (not escaped)
        if '<script>' in response_text.lower() or '<script ' in response_text.lower():
            # Make sure it's not escaped
            if '&lt;script' not in response_text.lower():
                return True
        
        return False
    
    def test_form(self, form_details):
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            form_details (dict): Form information from crawler
            
        Returns:
            list: List of vulnerabilities found
        """
        print(f"\n{Fore.CYAN}[TEST] Testing form: {form_details['action']}")
        print(f"{Fore.CYAN}[INFO] Method: {form_details['method'].upper()}")
        print(f"{Fore.CYAN}[INFO] Inputs: {len(form_details['inputs'])}")
        
        form_vulnerabilities = []
        
        # Test each input field with each payload
        for input_field in form_details['inputs']:
            input_name = input_field['name']
            
            # Skip non-text inputs
            if input_field['type'] in ['submit', 'button', 'image', 'reset']:
                continue
            
            print(f"{Fore.YELLOW}[TESTING] Input field: {input_name}")
            
            # Prepare baseline data for other fields
            baseline_data = {}
            for field in form_details['inputs']:
                if field['type'] not in ['submit', 'button', 'image', 'reset']:
                    baseline_data[field['name']] = 'test'
            
            tested_payloads = 0
            for payload in self.payloads:
                tested_payloads += 1
                
                # Create unique payload with marker
                unique_payload = payload.replace("XSS", f"{self.marker}{input_name}")
                
                # Prepare test data
                test_data = baseline_data.copy()
                test_data[input_name] = unique_payload
                
                try:
                    # Send request with payload
                    if form_details['method'] == 'get':
                        response = requests.get(
                            form_details['action'],
                            params=test_data,
                            timeout=10,
                            allow_redirects=True
                        )
                    else:  # POST
                        response = requests.post(
                            form_details['action'],
                            data=test_data,
                            timeout=10,
                            allow_redirects=True
                        )
                    
                    response_content = response.text
                    
                    # Check if payload is reflected
                    is_reflected, reflection_context = self.is_reflected(unique_payload, response_content)
                    
                    if is_reflected:
                        # Check if it's executable (not properly escaped)
                        is_executable = self.check_executable(unique_payload, response_content)
                        
                        if is_executable:
                            # VULNERABILITY FOUND!
                            vuln = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'subtype': 'Reflected' if form_details['method'] == 'get' else 'Potentially Stored',
                                'url': form_details['action'],
                                'method': form_details['method'].upper(),
                                'parameter': input_name,
                                'payload': unique_payload,
                                'evidence': f'Payload reflected in {reflection_context} context and appears executable',
                                'severity': 'HIGH'
                            }
                            form_vulnerabilities.append(vuln)
                            
                            print(f"{Fore.RED}[VULN!] XSS found in '{input_name}'")
                            print(f"{Fore.RED}        Payload: {unique_payload[:50]}...")
                            print(f"{Fore.RED}        Context: {reflection_context}")
                            
                            # Found XSS in this field, move to next field
                            break
                        
                        elif reflection_context == "html_encoded":
                            # Reflected but properly escaped - informational only
                            print(f"{Fore.YELLOW}[INFO] Payload reflected but HTML-encoded (safe)")
                
                except requests.exceptions.RequestException as e:
                    # Network error, skip this payload
                    continue
            
            print(f"{Fore.CYAN}[INFO] Tested {tested_payloads} payloads on '{input_name}'")
        
        return form_vulnerabilities
    
    def test_url_parameters(self, url):
        """
        Test URL parameters for reflected XSS.
        
        Args:
            url (str): URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        print(f"\n{Fore.CYAN}[TEST] Testing URL parameters: {url}")
        
        vulnerabilities = []
        
        # Add test parameter
        test_param = "xss_test"
        
        for payload in self.payloads[:10]:  # Test subset for URL params
            unique_payload = payload.replace("XSS", f"{self.marker}url")
            
            try:
                # Test as GET parameter
                response = requests.get(
                    url,
                    params={test_param: unique_payload},
                    timeout=10,
                    allow_redirects=True
                )
                
                response_content = response.text
                
                # Check if payload is reflected and executable
                is_reflected, reflection_context = self.is_reflected(unique_payload, response_content)
                
                if is_reflected:
                    is_executable = self.check_executable(unique_payload, response_content)
                    
                    if is_executable:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'subtype': 'Reflected (URL parameter)',
                            'url': url,
                            'method': 'GET',
                            'parameter': test_param,
                            'payload': unique_payload,
                            'evidence': f'Payload reflected in {reflection_context} context',
                            'severity': 'HIGH'
                        }
                        vulnerabilities.append(vuln)
                        
                        print(f"{Fore.RED}[VULN!] Reflected XSS in URL parameter")
                        print(f"{Fore.RED}        Payload: {unique_payload[:50]}...")
                        break
            
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def scan(self, forms, urls=None):
        """
        Scan all forms and URLs for XSS vulnerabilities.
        
        Args:
            forms (list): List of form dictionaries from crawler
            urls (list, optional): List of URLs to test for reflected XSS
            
        Returns:
            list: All vulnerabilities found
        """
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}XSS (CROSS-SITE SCRIPTING) SCAN")
        print(f"{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Testing {len(forms)} forms with {len(self.payloads)} payloads\n")
        
        all_vulnerabilities = []
        
        # Test forms
        for form in forms:
            form_vulns = self.test_form(form)
            all_vulnerabilities.extend(form_vulns)
        
        # Test URL parameters (optional)
        if urls:
            print(f"\n{Fore.YELLOW}Testing {len(urls)} URLs for reflected XSS\n")
            for url in urls:
                url_vulns = self.test_url_parameters(url)
                all_vulnerabilities.extend(url_vulns)
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}XSS SCAN COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        
        if all_vulnerabilities:
            print(f"{Fore.RED}[FOUND] {len(all_vulnerabilities)} XSS vulnerability(ies)")
        else:
            print(f"{Fore.GREEN}[CLEAN] No XSS vulnerabilities found")
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities