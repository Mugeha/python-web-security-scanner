# Scanner Usage Examples

## Basic Scan

Scan a target with default settings:
```bash
python scanner.py -u http://localhost:5000
```

## Custom Depth

Increase crawl depth to find more pages:
```bash
python scanner.py -u http://example.com -d 3
```

## Specific Tests Only

### SQL Injection Only
```bash
python scanner.py -u http://example.com --sqli-only
```

### XSS Only
```bash
python scanner.py -u http://example.com --xss-only
```

### Headers Only
```bash
python scanner.py -u http://example.com --headers-only
```

## Skip Specific Tests

### Skip XSS Testing
```bash
python scanner.py -u http://example.com --no-xss
```

### Skip SQL Injection Testing
```bash
python scanner.py -u http://example.com --no-sqli
```

## Custom Output

### Specify Report Name
```bash
python scanner.py -u http://example.com -o my_scan_report
```

### JSON Only (No HTML)
```bash
python scanner.py -u http://example.com --json-only
```

### No Report Files (Console Only)
```bash
python scanner.py -u http://example.com --no-report
```

## Complete Example

Full scan with custom settings:
```bash
python scanner.py -u http://testapp.com -d 3 -o testapp_security_scan
```

This will:
- Scan http://testapp.com
- Crawl up to 3 levels deep
- Run all security tests
- Save reports as `testapp_security_scan.html` and `testapp_security_scan.json`