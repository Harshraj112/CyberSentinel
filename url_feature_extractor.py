"""
URL Feature Extractor for Phishing Detection
Extracts 30 features from a given URL for ML model prediction
"""

import re
import urllib.request
from urllib.parse import urlparse, parse_qs
import socket
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import ssl
import warnings
warnings.filterwarnings('ignore')

class URLFeatureExtractor:
    """Extract features from URL for phishing detection"""
    
    def __init__(self, url):
        self.url = url
        self.domain = self.get_domain()
        self.soup = None
        self.whois_response = None
        
    def get_domain(self):
        """Extract domain from URL"""
        try:
            parsed = urlparse(self.url)
            domain = parsed.netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return ""
    
    def fetch_page_content(self):
        """Fetch webpage content"""
        try:
            response = requests.get(self.url, timeout=5, verify=False)
            self.soup = BeautifulSoup(response.content, 'html.parser')
        except:
            self.soup = None
    
    def get_whois_data(self):
        """Get WHOIS information"""
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None
    
    # Feature 1: having_IP_Address
    def having_ip_address(self):
        """Check if URL contains IP address"""
        try:
            match = re.search(
                r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))',
                self.url
            )
            return -1 if match else 1
        except:
            return 1
    
    # Feature 2: URL_Length
    def url_length(self):
        """Check URL length"""
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        else:
            return -1
    
    # Feature 3: Shortining_Service
    def shortening_service(self):
        """Check if URL uses shortening service"""
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                             r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                             r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                             r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|" \
                             r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|" \
                             r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|" \
                             r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                             r"tr\.im|link\.zip\.net"
        match = re.search(shortening_services, self.url)
        return -1 if match else 1
    
    # Feature 4: having_At_Symbol
    def having_at_symbol(self):
        """Check if @ symbol exists in URL"""
        return -1 if "@" in self.url else 1
    
    # Feature 5: double_slash_redirecting
    def double_slash_redirecting(self):
        """Check for // in URL path"""
        last_double_slash = self.url.rfind('//')
        return -1 if last_double_slash > 7 else 1
    
    # Feature 6: Prefix_Suffix
    def prefix_suffix(self):
        """Check for - in domain"""
        return -1 if '-' in self.domain else 1
    
    # Feature 7: having_Sub_Domain
    def having_sub_domain(self):
        """Count number of dots in domain"""
        dots = self.domain.count('.')
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1
    
    # Feature 8: SSLfinal_State
    def ssl_final_state(self):
        """Check SSL certificate"""
        try:
            if self.url.startswith('https'):
                return 1
            else:
                return -1
        except:
            return -1
    
    # Feature 9: Domain_registeration_length
    def domain_registration_length(self):
        """Check domain registration length"""
        try:
            if self.whois_response:
                expiration_date = self.whois_response.expiration_date
                creation_date = self.whois_response.creation_date
                
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if expiration_date and creation_date:
                    age = (expiration_date - creation_date).days
                    return 1 if age >= 365 else -1
            return -1
        except:
            return -1
    
    # Feature 10: Favicon
    def favicon(self):
        """Check if favicon is loaded from external domain"""
        try:
            if self.soup:
                for link in self.soup.find_all('link', rel='icon'):
                    href = link.get('href', '')
                    if href and self.domain not in href:
                        return -1
            return 1
        except:
            return 1
    
    # Feature 11: port
    def port(self):
        """Check for non-standard ports"""
        try:
            parsed = urlparse(self.url)
            port = parsed.port
            if port and port not in [80, 443]:
                return -1
            return 1
        except:
            return 1
    
    # Feature 12: HTTPS_token
    def https_token(self):
        """Check if 'https' appears in domain name"""
        return -1 if 'https' in self.domain else 1
    
    # Feature 13: Request_URL
    def request_url(self):
        """Check percentage of external objects"""
        try:
            if self.soup:
                total = 0
                external = 0
                for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe']):
                    src = tag.get('src', '')
                    if src:
                        total += 1
                        if self.domain not in src and src.startswith('http'):
                            external += 1
                
                if total > 0:
                    percentage = (external / total) * 100
                    if percentage < 22:
                        return 1
                    elif 22 <= percentage <= 61:
                        return 0
                    else:
                        return -1
            return 1
        except:
            return 1
    
    # Feature 14: URL_of_Anchor
    def url_of_anchor(self):
        """Check anchor tags"""
        try:
            if self.soup:
                total = 0
                unsafe = 0
                for anchor in self.soup.find_all('a'):
                    href = anchor.get('href', '')
                    if href:
                        total += 1
                        if href == '#' or href.startswith('javascript:') or self.domain not in href:
                            unsafe += 1
                
                if total > 0:
                    percentage = (unsafe / total) * 100
                    if percentage < 31:
                        return 1
                    elif 31 <= percentage <= 67:
                        return 0
                    else:
                        return -1
            return 1
        except:
            return 1
    
    # Feature 15: Links_in_tags
    def links_in_tags(self):
        """Check links in meta, script, and link tags"""
        try:
            if self.soup:
                total = 0
                external = 0
                for tag in self.soup.find_all(['meta', 'script', 'link']):
                    src = tag.get('href', tag.get('src', ''))
                    if src:
                        total += 1
                        if self.domain not in src and src.startswith('http'):
                            external += 1
                
                if total > 0:
                    percentage = (external / total) * 100
                    if percentage < 17:
                        return 1
                    elif 17 <= percentage <= 81:
                        return 0
                    else:
                        return -1
            return 1
        except:
            return 1
    
    # Feature 16: SFH (Server Form Handler)
    def sfh(self):
        """Check form action"""
        try:
            if self.soup:
                for form in self.soup.find_all('form'):
                    action = form.get('action', '')
                    if action == '' or action == 'about:blank':
                        return -1
                    elif self.domain not in action:
                        return 0
            return 1
        except:
            return 1
    
    # Feature 17: Submitting_to_email
    def submitting_to_email(self):
        """Check if form submits to email"""
        try:
            if self.soup:
                if re.search(r'mailto:', str(self.soup)):
                    return -1
            return 1
        except:
            return 1
    
    # Feature 18: Abnormal_URL
    def abnormal_url(self):
        """Check if URL is present in WHOIS"""
        try:
            if self.whois_response and self.whois_response.domain_name:
                return 1
            return -1
        except:
            return -1
    
    # Feature 19: Redirect
    def redirect(self):
        """Count number of redirects"""
        try:
            response = requests.get(self.url, timeout=5, allow_redirects=True)
            redirects = len(response.history)
            if redirects <= 1:
                return 1
            elif redirects <= 4:
                return 0
            else:
                return -1
        except:
            return 1
    
    # Feature 20: on_mouseover
    def on_mouseover(self):
        """Check for onMouseOver event"""
        try:
            if self.soup and 'onmouseover' in str(self.soup).lower():
                return -1
            return 1
        except:
            return 1
    
    # Feature 21: RightClick
    def right_click(self):
        """Check if right click is disabled"""
        try:
            if self.soup:
                if re.search(r'event\.button\s*==\s*2', str(self.soup)) or \
                   re.search(r'contextmenu', str(self.soup)):
                    return -1
            return 1
        except:
            return 1
    
    # Feature 22: popUpWidnow
    def popup_window(self):
        """Check for popup windows"""
        try:
            if self.soup and re.search(r'window\.open\(', str(self.soup)):
                return -1
            return 1
        except:
            return 1
    
    # Feature 23: Iframe
    def iframe(self):
        """Check for iframe"""
        try:
            if self.soup and self.soup.find_all('iframe'):
                return -1
            return 1
        except:
            return 1
    
    # Feature 24: age_of_domain
    def age_of_domain(self):
        """Check domain age"""
        try:
            if self.whois_response and self.whois_response.creation_date:
                creation_date = self.whois_response.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age = (datetime.now() - creation_date).days
                return 1 if age >= 180 else -1
            return -1
        except:
            return -1
    
    # Feature 25: DNSRecord
    def dns_record(self):
        """Check DNS record"""
        try:
            socket.gethostbyname(self.domain)
            return 1
        except:
            return -1
    
    # Feature 26: web_traffic
    def web_traffic(self):
        """Check web traffic (simplified)"""
        try:
            # This is a simplified version
            # In production, you'd use Alexa API or similar
            return 1
        except:
            return -1
    
    # Feature 27: Page_Rank
    def page_rank(self):
        """Check page rank (simplified)"""
        try:
            # This is a simplified version
            # In production, you'd use Google PageRank API
            return 1
        except:
            return -1
    
    # Feature 28: Google_Index
    def google_index(self):
        """Check if indexed by Google"""
        try:
            url = f"https://www.google.com/search?q=site:{self.domain}"
            response = requests.get(url, timeout=5)
            return 1 if self.domain in response.text else -1
        except:
            return -1
    
    # Feature 29: Links_pointing_to_page
    def links_pointing_to_page(self):
        """Check number of links pointing to page"""
        try:
            if self.soup:
                links = len(self.soup.find_all('a'))
                if links == 0:
                    return -1
                elif links <= 2:
                    return 0
                else:
                    return 1
            return 1
        except:
            return 1
    
    # Feature 30: Statistical_report
    def statistical_report(self):
        """Check if domain is in statistical report"""
        try:
            # This would check against known phishing databases
            # Simplified for now
            return 1
        except:
            return 1
    
    def extract_all_features(self):
        """Extract all 30 features from URL"""
        print(f"Extracting features from: {self.url}")
        
        # Fetch page content and WHOIS data
        self.fetch_page_content()
        self.get_whois_data()
        
        features = {
            'having_IP_Address': self.having_ip_address(),
            'URL_Length': self.url_length(),
            'Shortining_Service': self.shortening_service(),
            'having_At_Symbol': self.having_at_symbol(),
            'double_slash_redirecting': self.double_slash_redirecting(),
            'Prefix_Suffix': self.prefix_suffix(),
            'having_Sub_Domain': self.having_sub_domain(),
            'SSLfinal_State': self.ssl_final_state(),
            'Domain_registeration_length': self.domain_registration_length(),
            'Favicon': self.favicon(),
            'port': self.port(),
            'HTTPS_token': self.https_token(),
            'Request_URL': self.request_url(),
            'URL_of_Anchor': self.url_of_anchor(),
            'Links_in_tags': self.links_in_tags(),
            'SFH': self.sfh(),
            'Submitting_to_email': self.submitting_to_email(),
            'Abnormal_URL': self.abnormal_url(),
            'Redirect': self.redirect(),
            'on_mouseover': self.on_mouseover(),
            'RightClick': self.right_click(),
            'popUpWidnow': self.popup_window(),
            'Iframe': self.iframe(),
            'age_of_domain': self.age_of_domain(),
            'DNSRecord': self.dns_record(),
            'web_traffic': self.web_traffic(),
            'Page_Rank': self.page_rank(),
            'Google_Index': self.google_index(),
            'Links_pointing_to_page': self.links_pointing_to_page(),
            'Statistical_report': self.statistical_report()
        }
        
        return features


# Test function
if __name__ == "__main__":
    test_url = "https://www.google.com"
    extractor = URLFeatureExtractor(test_url)
    features = extractor.extract_all_features()
    
    print("\nExtracted Features:")
    for feature, value in features.items():
        print(f"{feature}: {value}")
