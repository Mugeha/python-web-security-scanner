#!/usr/bin/env python3
"""
Python Web Security Scanner
A comprehensive security scanner for web applications
"""

import argparse
import sys
import time
from datetime import datetime
from colorama import Fore, Style, init

# Import our modules
from modules.crawler import WebCrawler
from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.headers_checker import SecurityHeadersChecker
from modules.reporter import ReportGenerator

init(autoreset=True)

def print_banner():
    """Display the scanner banner."""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  {Fore.YELLOW}🔐  PYTHON WEB SECURITY SCANNER  🔐{Fore.CYAN}                    ║
║                                                           ║
║  {Fore.WHITE}Automated Web Application Security Testing Tool{Fore.CYAN}       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u http://localhost:5000
  python scanner.py -u http://example.com -d 3 --no-xss
  python scanner.py -u http://example.com --sqli-only -o custom_report
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (e.g., http://example.com)'
    )
    
    # Optional arguments
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=2,
        help='Maximum crawl depth (default: 2)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Output report filename (without extension)'
    )
    
    # Scan modules (can disable specific tests)
    parser.add_argument(
        '--sqli-only',
        action='store_true',
        help='Only run SQL injection tests'
    )
    
    parser.add_argument(
        '--xss-only',
        action='store_true',
        help='Only run XSS tests'
    )
    
    parser.add_argument(
        '--headers-only',
        action='store_true',
        help='Only check security headers'
    )
    
    parser.add_argument(
        '--no-sqli',
        action='store_true',
        help='Skip SQL injection tests'
    )
    
    parser.add_argument(
        '--no-xss',
        action='store_true',
        help='Skip XSS tests'
    )
    
    parser.add_argument(
        '--no-headers',
        action='store_true',
        help='Skip security headers check'
    )
    
    # Report options
    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Generate only JSON report (no HTML)'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Do not generate any report files'
    )
    
    return parser.parse_args()

def validate_url(url):
    """Validate the target URL."""
    if not url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://")
        return False
    return True

def run_scan(args):
    """Execute the security scan."""
    
    # Validate URL
    if not validate_url(args.url):
        sys.exit(1)
    
    # Start timing
    start_time = time.time()
    
    # Initialize scan data dictionary
    scan_data = {
        'target_url': args.url,
        'scan_start': datetime.now().isoformat(),
        'pages_crawled': 0,
        'forms_found': 0,
        'sqli_vulnerabilities': [],
        'xss_vulnerabilities': [],
        'headers_results': []
    }
    
    # Determine which modules to run
    run_sqli = not args.no_sqli and not (args.xss_only or args.headers_only)
    run_xss = not args.no_xss and not (args.sqli_only or args.headers_only)
    run_headers = not args.no_headers and not (args.sqli_only or args.xss_only)
    
    # If --sqli-only, --xss-only, or --headers-only specified
    if args.sqli_only:
        run_sqli, run_xss, run_headers = True, False, False
    elif args.xss_only:
        run_sqli, run_xss, run_headers = False, True, False
    elif args.headers_only:
        run_sqli, run_xss, run_headers = False, False, True
    
    print(f"\n{Fore.YELLOW}[INFO] Target: {args.url}")
    print(f"{Fore.YELLOW}[INFO] Max Depth: {args.depth}")
    print(f"{Fore.YELLOW}[INFO] Modules: ", end="")
    
    modules = []
    if run_sqli:
        modules.append("SQLi")
    if run_xss:
        modules.append("XSS")
    if run_headers:
        modules.append("Headers")
    print(", ".join(modules) + "\n")
    
    # ============================================================
    # PHASE 1: CRAWLING
    # ============================================================
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}PHASE 1: WEB CRAWLING")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    try:
        crawler = WebCrawler(target_url=args.url, max_depth=args.depth)
        crawl_results = crawler.start()
        
        scan_data['pages_crawled'] = crawl_results['total_pages']
        scan_data['forms_found'] = crawl_results['total_forms']
        
        if crawl_results['total_forms'] == 0:
            print(f"{Fore.YELLOW}[WARNING] No forms found. SQL injection and XSS tests will be limited.")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Crawling failed: {str(e)}")
        sys.exit(1)
    
    # ============================================================
    # PHASE 2: SQL INJECTION TESTING
    # ============================================================
    if run_sqli and crawl_results['forms']:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}PHASE 2: SQL INJECTION TESTING")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            sqli_detector = SQLiDetector()
            sqli_vulns = sqli_detector.scan(crawl_results['forms'])
            scan_data['sqli_vulnerabilities'] = sqli_vulns
        except Exception as e:
            print(f"{Fore.RED}[ERROR] SQL injection testing failed: {str(e)}")
    
    # ============================================================
    # PHASE 3: XSS TESTING
    # ============================================================
    if run_xss and crawl_results['forms']:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}PHASE 3: XSS TESTING")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            xss_detector = XSSDetector()
            xss_vulns = xss_detector.scan(
                forms=crawl_results['forms'],
                urls=crawl_results['visited_urls'][:5]  # Test first 5 URLs only
            )
            scan_data['xss_vulnerabilities'] = xss_vulns
        except Exception as e:
            print(f"{Fore.RED}[ERROR] XSS testing failed: {str(e)}")
    
    # ============================================================
    # PHASE 4: SECURITY HEADERS CHECK
    # ============================================================
    if run_headers:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}PHASE 4: SECURITY HEADERS CHECK")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            headers_checker = SecurityHeadersChecker()
            headers_results = headers_checker.scan([args.url])
            scan_data['headers_results'] = headers_results
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Headers check failed: {str(e)}")
    
    # ============================================================
    # CALCULATE SCAN DURATION
    # ============================================================
    end_time = time.time()
    duration = end_time - start_time
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    scan_data['scan_duration'] = f"{minutes}m {seconds}s"
    
    # ============================================================
    # GENERATE REPORTS
    # ============================================================
    if not args.no_report:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}GENERATING REPORTS")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            reporter = ReportGenerator()
            
            # Generate HTML report
            if not args.json_only:
                html_filename = args.output + ".html" if args.output else None
                html_path = reporter.generate_html_report(scan_data, html_filename)
                print(f"{Fore.GREEN}[HTML] {html_path}")
            
            # Generate JSON report
            json_filename = args.output + ".json" if args.output else None
            json_path = reporter.generate_json_report(scan_data, json_filename)
            print(f"{Fore.GREEN}[JSON] {json_path}")
            
            # Print summary
            reporter.print_summary(scan_data)
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Report generation failed: {str(e)}")
    else:
        # Just print summary if no report requested
        reporter = ReportGenerator()
        reporter.print_summary(scan_data)
    
    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}SCAN COMPLETE!")
    print(f"{Fore.GREEN}{'='*60}\n")
    
    total_vulns = len(scan_data['sqli_vulnerabilities']) + len(scan_data['xss_vulnerabilities'])
    
    if total_vulns > 0:
        print(f"{Fore.RED}  VULNERABILITIES DETECTED: {total_vulns}")
        print(f"{Fore.YELLOW}Review the generated reports for details.\n")
    else:
        print(f"{Fore.GREEN} NO CRITICAL VULNERABILITIES DETECTED")
        print(f"{Fore.YELLOW}Note: Some security headers may be missing.\n")
    
    return 0 if total_vulns == 0 else 1

def main():
    """Main entry point."""
    print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Run scan
    try:
        exit_code = run_scan(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[INTERRUPTED] Scan cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n{Fore.RED}[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()