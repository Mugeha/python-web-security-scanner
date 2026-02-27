from modules.crawler import WebCrawler
from modules.xss_detector import XSSDetector

# Step 1: Crawl the target
print("Step 1: Crawling target application...\n")
crawler = WebCrawler(
    target_url='http://127.0.0.1:5000',
    max_depth=2
)
crawl_results = crawler.start()

# Step 2: Test forms for XSS
print("\nStep 2: Testing for XSS vulnerabilities...\n")
xss_detector = XSSDetector(payloads_file='payloads/xss.txt')
vulnerabilities = xss_detector.scan(
    forms=crawl_results['forms'],
    urls=crawl_results['visited_urls']
)

# Step 3: Display results
print("\n" + "="*60)
print("VULNERABILITY SUMMARY")
print("="*60)

if vulnerabilities:
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n[Vulnerability #{i}]")
        print(f"  Type: {vuln['type']}")
        print(f"  Subtype: {vuln['subtype']}")
        print(f"  Severity: {vuln['severity']}")
        print(f"  URL: {vuln['url']}")
        print(f"  Method: {vuln['method']}")
        print(f"  Parameter: {vuln['parameter']}")
        print(f"  Payload: {vuln['payload'][:80]}...")
        print(f"  Evidence: {vuln['evidence']}")
else:
    print("\nNo XSS vulnerabilities found.")