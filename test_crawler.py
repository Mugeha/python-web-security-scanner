from modules.crawler import WebCrawler

# Test on your expense tracker
crawler = WebCrawler(
    target_url='http://127.0.0.1:5000',
    max_depth=2
)

results = crawler.start()

print("\n" + "="*50)
print("CRAWL RESULTS")
print("="*50)
print(f"Total pages visited: {results['total_pages']}")
print(f"Total forms found: {results['total_forms']}")

print("\nForms discovered:")
for i, form in enumerate(results['forms'], 1):
    print(f"\n[Form {i}]")
    print(f"  URL: {form['url']}")
    print(f"  Action: {form['action']}")
    print(f"  Method: {form['method']}")
    print(f"  Inputs: {len(form['inputs'])}")
    for inp in form['inputs']:
        print(f"    - {inp['name']} ({inp['type']})")