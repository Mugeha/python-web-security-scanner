import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class WebCrawler:
    """
    Web crawler that discovers URLs, forms, and parameters on a target website.
    """
    
    def __init__(self, target_url, max_depth=2):
        """
        Initialize the crawler.
        
        Args:
            target_url (str): The starting URL to crawl
            max_depth (int): Maximum depth to crawl (default: 2)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.domain = urlparse(target_url).netloc
        
    def is_valid_url(self, url):
        """
        Check if URL belongs to the target domain.
        
        Args:
            url (str): URL to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        parsed = urlparse(url)
        return parsed.netloc == self.domain
    
    def get_page_content(self, url):
        """
        Fetch page content with error handling.
        
        Args:
            url (str): URL to fetch
            
        Returns:
            str: Page HTML content or None if error
        """
        try:
            response = requests.get(url, timeout=5, verify=False)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] Failed to fetch {url}: {str(e)}")
            return None
    
    def extract_links(self, url, html_content):
        """
        Extract all links from HTML content.
        
        Args:
            url (str): Base URL for resolving relative links
            html_content (str): HTML content to parse
            
        Returns:
            set: Set of discovered URLs
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        # Find all <a> tags with href attribute
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Convert relative URLs to absolute
            absolute_url = urljoin(url, href)
            
            # Only include URLs from the same domain
            if self.is_valid_url(absolute_url):
                # Remove URL fragments (#section)
                absolute_url = absolute_url.split('#')[0]
                links.add(absolute_url)
        
        return links
    
    def extract_forms(self, url, html_content):
        """
        Extract all forms from HTML content.
        
        Args:
            url (str): URL where form was found
            html_content (str): HTML content to parse
            
        Returns:
            list: List of form dictionaries
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Extract all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                
                if input_name:  # Only include inputs with names
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_tag.get('value', '')
                    })
            
            forms.append(form_details)
        
        return forms
    
    def crawl(self, url=None, depth=0):
        """
        Recursively crawl website starting from URL.
        
        Args:
            url (str): URL to crawl (uses target_url if None)
            depth (int): Current crawl depth
        """
        if url is None:
            url = self.target_url
        
        # Stop if max depth reached
        if depth > self.max_depth:
            return
        
        # Skip if already visited
        if url in self.visited_urls:
            return
        
        print(f"{Fore.CYAN}[CRAWL] Depth {depth}: {url}")
        self.visited_urls.add(url)
        
        # Fetch page content
        html_content = self.get_page_content(url)
        if not html_content:
            return
        
        # Extract forms
        page_forms = self.extract_forms(url, html_content)
        self.forms.extend(page_forms)
        
        if page_forms:
            print(f"{Fore.GREEN}[FORMS] Found {len(page_forms)} form(s) on {url}")
        
        # Extract and crawl links
        links = self.extract_links(url, html_content)
        self.discovered_urls.update(links)
        
        # Recursively crawl discovered links
        for link in links:
            if link not in self.visited_urls:
                self.crawl(link, depth + 1)
    
    def start(self):
        """
        Start the crawling process and return results.
        
        Returns:
            dict: Crawl results containing URLs and forms
        """
        print(f"{Fore.YELLOW}[START] Crawling {self.target_url}")
        print(f"{Fore.YELLOW}[INFO] Max depth: {self.max_depth}")
        print(f"{Fore.YELLOW}[INFO] Target domain: {self.domain}\n")
        
        self.crawl()
        
        results = {
            'target': self.target_url,
            'visited_urls': list(self.visited_urls),
            'discovered_urls': list(self.discovered_urls),
            'forms': self.forms,
            'total_pages': len(self.visited_urls),
            'total_forms': len(self.forms)
        }
        
        print(f"\n{Fore.GREEN}[COMPLETE] Crawl finished!")
        print(f"{Fore.GREEN}[STATS] Visited {results['total_pages']} pages")
        print(f"{Fore.GREEN}[STATS] Found {results['total_forms']} forms\n")
        
        return results