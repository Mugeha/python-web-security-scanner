from modules.crawler import WebCrawler
from modules.headers_checker import SecurityHeadersChecker

# Step 1: Crawl to get URLs
print("Step 1: Crawling target application...\n")
crawler = WebCrawler(
    target_url='http://127.0.0.1:5000',
    max_depth=1
)
crawl_results = crawler.start()

# Step 2: Check security headers
print("\nStep 2: Checking security headers...\n")
headers_checker = SecurityHeadersChecker()

# Check just the main URL (checking every URL would be redundant)
results = headers_checker.scan([crawl_results['target']])

# Step 3: Display summary
if results:
    summary = headers_checker.generate_summary(results)
    print(summary)