import requests
from colorama import Fore, Style, init

init(autoreset=True)

class SecurityHeadersChecker:
    """
    Security headers analyzer.
    Checks for presence and proper configuration of security headers.
    """
    
    def __init__(self):
        """Initialize the security headers checker."""
        self.findings = []
        
        # Define security headers and their purposes
        self.security_headers = {
            'Content-Security-Policy': {
                'purpose': 'Prevents XSS attacks by controlling resource loading',
                'severity': 'HIGH',
                'recommendation': "Add: Content-Security-Policy: default-src 'self'"
            },
            'X-Frame-Options': {
                'purpose': 'Prevents clickjacking attacks',
                'severity': 'MEDIUM',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'purpose': 'Prevents MIME-sniffing attacks',
                'severity': 'MEDIUM',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'Strict-Transport-Security': {
                'purpose': 'Forces HTTPS connections',
                'severity': 'HIGH',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'X-XSS-Protection': {
                'purpose': 'Enables browser XSS filtering (legacy)',
                'severity': 'LOW',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'purpose': 'Controls referrer information leakage',
                'severity': 'LOW',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'purpose': 'Controls browser features and APIs',
                'severity': 'LOW',
                'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
            }
        }
    
    def check_url(self, url):
        """
        Check security headers for a given URL.
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: Analysis results
        """
        print(f"\n{Fore.CYAN}[CHECK] Analyzing security headers for: {url}")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            missing_headers = []
            present_headers = []
            weak_headers = []
            
            # Check each security header
            for header_name, header_info in self.security_headers.items():
                if header_name in headers:
                    present_headers.append({
                        'name': header_name,
                        'value': headers[header_name],
                        'purpose': header_info['purpose']
                    })
                    print(f"{Fore.GREEN}[PRESENT] {header_name}")
                    
                    # Check for weak configurations
                    self._check_header_strength(header_name, headers[header_name], header_info)
                else:
                    missing_headers.append({
                        'name': header_name,
                        'purpose': header_info['purpose'],
                        'severity': header_info['severity'],
                        'recommendation': header_info['recommendation']
                    })
                    
                    severity_color = {
                        'HIGH': Fore.RED,
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.CYAN
                    }.get(header_info['severity'], Fore.WHITE)
                    
                    print(f"{severity_color}[MISSING] {header_name} ({header_info['severity']})")
            
            # Check for dangerous headers
            dangerous_headers = self._check_dangerous_headers(headers)
            
            results = {
                'url': url,
                'total_checked': len(self.security_headers),
                'present': len(present_headers),
                'missing': len(missing_headers),
                'present_headers': present_headers,
                'missing_headers': missing_headers,
                'weak_headers': weak_headers,
                'dangerous_headers': dangerous_headers,
                'status_code': response.status_code
            }
            
            return results
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] Failed to check headers: {str(e)}")
            return None
    
    def _check_header_strength(self, header_name, header_value, header_info):
        """
        Check if a present header has weak configuration.
        
        Args:
            header_name (str): Header name
            header_value (str): Header value
            header_info (dict): Header information
        """
        weak_configs = []
        
        if header_name == 'Content-Security-Policy':
            # Check for overly permissive CSP
            if 'unsafe-inline' in header_value:
                weak_configs.append("Contains 'unsafe-inline' which allows inline scripts")
            if 'unsafe-eval' in header_value:
                weak_configs.append("Contains 'unsafe-eval' which allows eval()")
            if '*' in header_value:
                weak_configs.append("Contains wildcard (*) which allows any source")
        
        elif header_name == 'X-Frame-Options':
            # Check for weak X-Frame-Options
            if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                weak_configs.append(f"Weak value: {header_value}")
        
        elif header_name == 'Strict-Transport-Security':
            # Check HSTS configuration
            if 'max-age' not in header_value.lower():
                weak_configs.append("Missing 'max-age' directive")
            elif 'max-age=0' in header_value.lower():
                weak_configs.append("HSTS is disabled (max-age=0)")
            
            # Extract max-age value
            import re
            max_age_match = re.search(r'max-age=(\d+)', header_value, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    weak_configs.append(f"max-age too short: {max_age} seconds (recommend: 31536000)")
        
        if weak_configs:
            self.findings.append({
                'type': 'Weak Header Configuration',
                'header': header_name,
                'value': header_value,
                'issues': weak_configs,
                'severity': 'MEDIUM'
            })
            print(f"{Fore.YELLOW}[WEAK] {header_name} has weak configuration:")
            for issue in weak_configs:
                print(f"       - {issue}")
    
    def _check_dangerous_headers(self, headers):
        """
        Check for presence of dangerous/information-leaking headers.
        
        Args:
            headers (dict): Response headers
            
        Returns:
            list: List of dangerous headers found
        """
        dangerous = []
        
        # Headers that leak information
        info_leak_headers = {
            'Server': 'Reveals web server software and version',
            'X-Powered-By': 'Reveals backend technology',
            'X-AspNet-Version': 'Reveals ASP.NET version',
            'X-AspNetMvc-Version': 'Reveals ASP.NET MVC version'
        }
        
        for header, description in info_leak_headers.items():
            if header in headers:
                dangerous.append({
                    'header': header,
                    'value': headers[header],
                    'risk': description,
                    'severity': 'LOW'
                })
                print(f"{Fore.YELLOW}[INFO LEAK] {header}: {headers[header]}")
                print(f"             Risk: {description}")
        
        return dangerous
    
    def scan(self, urls):
        """
        Scan multiple URLs for security headers.
        
        Args:
            urls (list): List of URLs to check
            
        Returns:
            list: Results for all URLs
        """
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}SECURITY HEADERS SCAN")
        print(f"{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Checking {len(urls)} URL(s)\n")
        
        all_results = []
        
        for url in urls:
            result = self.check_url(url)
            if result:
                all_results.append(result)
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}SECURITY HEADERS SCAN COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        
        # Summary statistics
        if all_results:
            total_missing = sum(r['missing'] for r in all_results)
            total_present = sum(r['present'] for r in all_results)
            
            print(f"\n{Fore.CYAN}[SUMMARY]")
            print(f"  URLs scanned: {len(all_results)}")
            print(f"  Total headers present: {total_present}")
            print(f"  Total headers missing: {total_missing}")
            
            if total_missing > 0:
                print(f"\n{Fore.YELLOW}[RECOMMENDATION] Add missing security headers to improve security posture")
        
        return all_results
    
    def generate_summary(self, results):
        """
        Generate a text summary of findings.
        
        Args:
            results (list): Scan results
            
        Returns:
            str: Formatted summary
        """
        if not results:
            return "No results to summarize."
        
        summary = []
        summary.append("\n" + "="*60)
        summary.append("SECURITY HEADERS ANALYSIS SUMMARY")
        summary.append("="*60 + "\n")
        
        for result in results:
            summary.append(f"URL: {result['url']}")
            summary.append(f"Status: {result['status_code']}")
            summary.append(f"Headers Present: {result['present']}/{result['total_checked']}\n")
            
            if result['missing_headers']:
                summary.append("Missing Headers:")
                for header in result['missing_headers']:
                    summary.append(f"  [{header['severity']}] {header['name']}")
                    summary.append(f"      Purpose: {header['purpose']}")
                    summary.append(f"      Fix: {header['recommendation']}\n")
            
            if result['dangerous_headers']:
                summary.append("Information Disclosure:")
                for header in result['dangerous_headers']:
                    summary.append(f"  {header['header']}: {header['value']}")
                    summary.append(f"      Risk: {header['risk']}\n")
            
            summary.append("-" * 60 + "\n")
        
        return "\n".join(summary)