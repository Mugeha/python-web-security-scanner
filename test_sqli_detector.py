from modules.crawler import WebCrawler
from modules.sqli_detector import SQLiDetector

# Step 1: Crawl the target
print("Step 1: Crawling target application...\n")
crawler = WebCrawler(
    target_url='http://127.0.0.1:5000',
    max_depth=2
)
crawl_results = crawler.start()

# Step 2: Test forms for SQL injection
print("\nStep 2: Testing for SQL injection vulnerabilities...\n")
sqli_detector = SQLiDetector(payloads_file='payloads/sqli.txt')
vulnerabilities = sqli_detector.scan(crawl_results['forms'])

# Step 3: Display results
print("\n" + "="*60)
print("VULNERABILITY SUMMARY")
print("="*60)

if vulnerabilities:
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n[Vulnerability #{i}]")
        print(f"  Type: {vuln['type']}")
        print(f"  Severity: {vuln['severity']}")
        print(f"  URL: {vuln['url']}")
        print(f"  Method: {vuln['method']}")
        print(f"  Parameter: {vuln['parameter']}")
        print(f"  Payload: {vuln['payload']}")
        print(f"  Evidence: {vuln['evidence']}")
else:
    print("\nNo SQL injection vulnerabilities found.")