from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os
from colorama import Fore, init

init(autoreset=True)

class ReportGenerator:
    """
    Generates HTML and JSON reports from scan results.
    """
    
    def __init__(self, output_dir='reports'):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str): Directory to save reports
        """
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Setup Jinja2 environment
        self.env = Environment(loader=FileSystemLoader('templates'))
    
    def categorize_by_severity(self, vulnerabilities):
        """
        Count vulnerabilities by severity.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            
        Returns:
            dict: Counts by severity level
        """
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def generate_html_report(self, scan_data, filename=None):
        """
        Generate HTML report from scan data.
        
        Args:
            scan_data (dict): Complete scan results
            filename (str, optional): Output filename
            
        Returns:
            str: Path to generated report
        """
        print(f"\n{Fore.CYAN}[REPORT] Generating HTML report...")
        
        # Generate filename if not provided
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_name = scan_data.get('target_url', 'scan').replace('http://', '').replace('https://', '').replace('/', '_')
            filename = f"scan_report_{target_name}_{timestamp}.html"
        
        # Prepare template data
        all_vulns = []
        all_vulns.extend(scan_data.get('sqli_vulnerabilities', []))
        all_vulns.extend(scan_data.get('xss_vulnerabilities', []))
        
        severity_counts = self.categorize_by_severity(all_vulns)
        
        # Add missing headers as vulnerabilities for report
        missing_headers = []
        if scan_data.get('headers_results'):
            for result in scan_data['headers_results']:
                missing_headers.extend(result.get('missing_headers', []))
        
        template_data = {
            'target_url': scan_data.get('target_url', 'Unknown'),
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'pages_crawled': scan_data.get('pages_crawled', 0),
            'forms_found': scan_data.get('forms_found', 0),
            'total_vulns': len(all_vulns),
            'scan_duration': scan_data.get('scan_duration', 'N/A'),
            'critical_count': severity_counts['CRITICAL'],
            'high_count': severity_counts['HIGH'],
            'medium_count': severity_counts['MEDIUM'],
            'low_count': severity_counts['LOW'],
            'vulnerabilities': all_vulns,
            'missing_headers': missing_headers
        }
        
        # Render template
        template = self.env.get_template('report_template.html')
        html_content = template.render(**template_data)
        
        # Save report
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[SUCCESS] HTML report saved: {output_path}")
        return output_path
    
    def generate_json_report(self, scan_data, filename=None):
        """
        Generate JSON report from scan data.
        
        Args:
            scan_data (dict): Complete scan results
            filename (str, optional): Output filename
            
        Returns:
            str: Path to generated report
        """
        import json
        
        print(f"\n{Fore.CYAN}[REPORT] Generating JSON report...")
        
        # Generate filename if not provided
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_name = scan_data.get('target_url', 'scan').replace('http://', '').replace('https://', '').replace('/', '_')
            filename = f"scan_report_{target_name}_{timestamp}.json"
        
        # Prepare JSON data
        json_data = {
            'scan_info': {
                'target_url': scan_data.get('target_url', 'Unknown'),
                'scan_date': datetime.now().isoformat(),
                'pages_crawled': scan_data.get('pages_crawled', 0),
                'forms_found': scan_data.get('forms_found', 0),
                'scan_duration': scan_data.get('scan_duration', 'N/A')
            },
            'vulnerabilities': {
                'sql_injection': scan_data.get('sqli_vulnerabilities', []),
                'xss': scan_data.get('xss_vulnerabilities', []),
                'total': len(scan_data.get('sqli_vulnerabilities', [])) + len(scan_data.get('xss_vulnerabilities', []))
            },
            'security_headers': scan_data.get('headers_results', [])
        }
        
        # Save report
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"{Fore.GREEN}[SUCCESS] JSON report saved: {output_path}")
        return output_path
    
    def print_summary(self, scan_data):
        """
        Print a text summary to console.
        
        Args:
            scan_data (dict): Complete scan results
        """
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}SCAN SUMMARY")
        print(f"{Fore.YELLOW}{'='*60}\n")
        
        print(f"{Fore.CYAN}Target: {scan_data.get('target_url', 'Unknown')}")
        print(f"{Fore.CYAN}Pages Crawled: {scan_data.get('pages_crawled', 0)}")
        print(f"{Fore.CYAN}Forms Found: {scan_data.get('forms_found', 0)}")
        print(f"{Fore.CYAN}Scan Duration: {scan_data.get('scan_duration', 'N/A')}\n")
        
        sqli_vulns = scan_data.get('sqli_vulnerabilities', [])
        xss_vulns = scan_data.get('xss_vulnerabilities', [])
        
        print(f"{Fore.YELLOW}Vulnerabilities Found:")
        print(f"  {Fore.RED}SQL Injection: {len(sqli_vulns)}")
        print(f"  {Fore.RED}Cross-Site Scripting (XSS): {len(xss_vulns)}")
        
        total_vulns = len(sqli_vulns) + len(xss_vulns)
        
        if total_vulns == 0:
            print(f"\n{Fore.GREEN}✅ No vulnerabilities detected!")
        else:
            print(f"\n{Fore.RED}⚠️  Total vulnerabilities: {total_vulns}")
        
        print(f"\n{Fore.YELLOW}{'='*60}\n")