#!/usr/bin/env python3
"""
Subdomain Takeover Scanner
A comprehensive tool for detecting potential subdomain takeover vulnerabilities
"""

import dns.resolver
import requests
import concurrent.futures
import argparse
import json
import re
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse
import socket
import time
from datetime import datetime

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Known vulnerable CNAME patterns and error signatures
FINGERPRINTS = {
    'AWS/S3': {
        'cname': ['s3.amazonaws.com', 's3-website'],
        'http': ['NoSuchBucket', 'The specified bucket does not exist'],
        'vulnerable': True
    },
    'GitHub Pages': {
        'cname': ['github.io'],
        'http': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
        'vulnerable': True
    },
    'Heroku': {
        'cname': ['herokuapp.com', 'herokussl.com'],
        'http': ['No such app', 'There\'s nothing here', 'herokucdn.com/error-pages'],
        'vulnerable': True
    },
    'Shopify': {
        'cname': ['myshopify.com'],
        'http': ['Sorry, this shop is currently unavailable', 'Only one step left'],
        'vulnerable': True
    },
    'Tumblr': {
        'cname': ['tumblr.com'],
        'http': ['Whatever you were looking for doesn\'t currently exist', 'There\'s nothing here'],
        'vulnerable': True
    },
    'WordPress': {
        'cname': ['wordpress.com'],
        'http': ['Do you want to register'],
        'vulnerable': True
    },
    'Ghost': {
        'cname': ['ghost.io'],
        'http': ['The thing you were looking for is no longer here'],
        'vulnerable': True
    },
    'Zendesk': {
        'cname': ['zendesk.com'],
        'http': ['Help Center Closed', 'this help center no longer exists'],
        'vulnerable': True
    },
    'Fastly': {
        'cname': ['fastly.net'],
        'http': ['Fastly error: unknown domain'],
        'vulnerable': True
    },
    'Pantheon': {
        'cname': ['pantheonsite.io'],
        'http': ['404 error unknown site'],
        'vulnerable': True
    },
    'Azure': {
        'cname': ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com'],
        'http': ['404 Web Site not found', 'Error 404 - Web app not found'],
        'vulnerable': True
    },
    'Unbounce': {
        'cname': ['unbouncepages.com'],
        'http': ['The requested URL was not found on this server'],
        'vulnerable': True
    },
    'Surge.sh': {
        'cname': ['surge.sh'],
        'http': ['project not found'],
        'vulnerable': True
    },
    'Bitbucket': {
        'cname': ['bitbucket.io'],
        'http': ['Repository not found'],
        'vulnerable': True
    },
    'Netlify': {
        'cname': ['netlify.com', 'netlify.app'],
        'http': ['Not Found - Request ID'],
        'vulnerable': True
    },
    'Cargo': {
        'cname': ['cargocollective.com'],
        'http': ['404 Not Found'],
        'vulnerable': True
    },
    'Statuspage': {
        'cname': ['statuspage.io'],
        'http': ['You are being', 'redirected'],
        'vulnerable': True
    },
    'Uservoice': {
        'cname': ['uservoice.com'],
        'http': ['This UserVoice subdomain is currently unavailable'],
        'vulnerable': True
    },
    'Cloudfront': {
        'cname': ['cloudfront.net'],
        'http': ['ERROR: The request could not be satisfied', 'Bad request'],
        'vulnerable': True
    }
}

class SubdomainTakeoverScanner:
    def __init__(self, domain: str, wordlist: str = None, threads: int = 10, 
                 timeout: int = 5, verbose: bool = False, output: str = None):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.subdomains = set()
        self.vulnerable_subdomains = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    def print_banner(self):
        """Print tool banner"""
        ascii_art = f"""{Colors.FAIL}
██████╗ ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔════╝██║   ██║██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╗ ██║   ██║██████╔╝███████║███████║██║ █╗ ██║█████╔╝ 
╚════██║██║   ██║██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ 
██████╔╝╚██████╔╝██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{Colors.ENDC}
{Colors.OKCYAN}                    Created by 0xS4r4n9{Colors.ENDC}"""
        
        banner = f"""
{ascii_art}

{Colors.OKBLUE}
╔═══════════════════════════════════════════════════════════╗
║           Subdomain Takeover Scanner v1.0                 ║
║         Detect Vulnerable Subdomain Configurations        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.OKCYAN}Target Domain:{Colors.ENDC} {self.domain}
{Colors.OKCYAN}Threads:{Colors.ENDC} {self.threads}
{Colors.OKCYAN}Timeout:{Colors.ENDC} {self.timeout}s
{Colors.OKCYAN}Started:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        print(banner)
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with color coding"""
        colors = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "VULN": Colors.FAIL + Colors.BOLD
        }
        color = colors.get(level, Colors.ENDC)
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{color}[{timestamp}] [{level}]{Colors.ENDC} {message}")
    
    def enumerate_subdomains_passive(self) -> Set[str]:
        """Enumerate subdomains using passive techniques"""
        self.log("Starting passive subdomain enumeration...")
        subdomains = set()
        
        # Try certificate transparency logs
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines as crt.sh may return multiple domains
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and '*' not in subdomain:
                            subdomains.add(subdomain)
                self.log(f"Found {len(subdomains)} subdomains from crt.sh", "SUCCESS")
        except Exception as e:
            if self.verbose:
                self.log(f"crt.sh enumeration failed: {str(e)}", "WARNING")
        
        return subdomains
    
    def enumerate_subdomains_wordlist(self) -> Set[str]:
        """Enumerate subdomains using wordlist"""
        if not self.wordlist:
            return set()
        
        self.log(f"Starting wordlist-based enumeration from {self.wordlist}...")
        subdomains = set()
        
        try:
            with open(self.wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_word = {
                    executor.submit(self.check_subdomain_exists, f"{word}.{self.domain}"): word 
                    for word in words
                }
                
                for future in concurrent.futures.as_completed(future_to_word):
                    subdomain = future.result()
                    if subdomain:
                        subdomains.add(subdomain)
                        if self.verbose:
                            self.log(f"Found: {subdomain}", "SUCCESS")
            
            self.log(f"Found {len(subdomains)} subdomains from wordlist", "SUCCESS")
        except FileNotFoundError:
            self.log(f"Wordlist file not found: {self.wordlist}", "ERROR")
        except Exception as e:
            self.log(f"Wordlist enumeration failed: {str(e)}", "ERROR")
        
        return subdomains
    
    def check_subdomain_exists(self, subdomain: str) -> str:
        """Check if a subdomain exists via DNS resolution"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return subdomain if answers else None
        except:
            return None
    
    def get_cname_records(self, subdomain: str) -> List[str]:
        """Get CNAME records for a subdomain"""
        cnames = []
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cnames.append(str(rdata.target).rstrip('.'))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            if self.verbose:
                self.log(f"CNAME lookup failed for {subdomain}: {str(e)}", "WARNING")
        
        return cnames
    
    def get_http_response(self, subdomain: str) -> Tuple[int, str]:
        """Get HTTP response from subdomain"""
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    verify=False
                )
                return response.status_code, response.text
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                continue
            except Exception as e:
                if self.verbose:
                    self.log(f"HTTP request failed for {subdomain}: {str(e)}", "WARNING")
        
        return None, None
    
    def check_fingerprint(self, cnames: List[str], http_response: str) -> Tuple[bool, str, str]:
        """Check if subdomain matches known vulnerable fingerprints"""
        for service, fingerprint in FINGERPRINTS.items():
            # Check CNAME patterns
            cname_match = False
            matched_cname = ""
            for cname in cnames:
                for pattern in fingerprint['cname']:
                    if pattern in cname.lower():
                        cname_match = True
                        matched_cname = cname
                        break
                if cname_match:
                    break
            
            # Check HTTP response patterns
            http_match = False
            if http_response and fingerprint.get('vulnerable'):
                for pattern in fingerprint['http']:
                    if pattern.lower() in http_response.lower():
                        http_match = True
                        break
            
            # If both CNAME and HTTP patterns match, it's likely vulnerable
            if cname_match and http_match:
                return True, service, matched_cname
        
        return False, "", ""
    
    def check_subdomain_takeover(self, subdomain: str) -> Dict:
        """Check if a subdomain is vulnerable to takeover"""
        result = {
            'subdomain': subdomain,
            'vulnerable': False,
            'service': None,
            'cname': [],
            'evidence': []
        }
        
        # Get CNAME records
        cnames = self.get_cname_records(subdomain)
        result['cname'] = cnames
        
        if not cnames:
            return result
        
        # Get HTTP response
        status_code, http_response = self.get_http_response(subdomain)
        
        # Check fingerprints
        vulnerable, service, matched_cname = self.check_fingerprint(cnames, http_response)
        
        if vulnerable:
            result['vulnerable'] = True
            result['service'] = service
            result['evidence'].append(f"CNAME points to: {matched_cname}")
            result['evidence'].append(f"Service identified: {service}")
            if status_code:
                result['evidence'].append(f"HTTP Status: {status_code}")
            
            self.log(
                f"VULNERABLE: {subdomain} -> {service} ({matched_cname})", 
                "VULN"
            )
        
        return result
    
    def scan(self):
        """Main scanning function"""
        self.print_banner()
        
        # Enumerate subdomains
        self.log("Enumerating subdomains...")
        
        # Passive enumeration
        passive_subs = self.enumerate_subdomains_passive()
        self.subdomains.update(passive_subs)
        
        # Wordlist enumeration
        if self.wordlist:
            wordlist_subs = self.enumerate_subdomains_wordlist()
            self.subdomains.update(wordlist_subs)
        
        if not self.subdomains:
            self.log("No subdomains found. Try using a wordlist with -w option.", "WARNING")
            return
        
        self.log(f"Total unique subdomains found: {len(self.subdomains)}", "INFO")
        
        # Check for takeover vulnerabilities
        self.log("Checking for subdomain takeover vulnerabilities...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain_takeover, sub): sub 
                for sub in self.subdomains
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result['vulnerable']:
                    self.vulnerable_subdomains.append(result)
        
        # Print summary
        self.print_summary()
        
        # Save results
        if self.output:
            self.save_results()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Total Subdomains Scanned:{Colors.ENDC} {len(self.subdomains)}")
        print(f"{Colors.FAIL}{Colors.BOLD}Vulnerable Subdomains:{Colors.ENDC} {len(self.vulnerable_subdomains)}\n")
        
        if self.vulnerable_subdomains:
            print(f"{Colors.FAIL}{Colors.BOLD}VULNERABLE SUBDOMAINS:{Colors.ENDC}\n")
            for vuln in self.vulnerable_subdomains:
                print(f"{Colors.FAIL}[!]{Colors.ENDC} {Colors.BOLD}{vuln['subdomain']}{Colors.ENDC}")
                print(f"    {Colors.WARNING}Service:{Colors.ENDC} {vuln['service']}")
                print(f"    {Colors.WARNING}CNAME:{Colors.ENDC} {', '.join(vuln['cname'])}")
                for evidence in vuln['evidence']:
                    print(f"    {Colors.OKBLUE}└─{Colors.ENDC} {evidence}")
                print()
        else:
            print(f"{Colors.OKGREEN}No vulnerable subdomains found!{Colors.ENDC}\n")
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            results = {
                'scan_info': {
                    'domain': self.domain,
                    'timestamp': datetime.now().isoformat(),
                    'total_subdomains': len(self.subdomains),
                    'vulnerable_count': len(self.vulnerable_subdomains)
                },
                'subdomains': list(self.subdomains),
                'vulnerable': self.vulnerable_subdomains
            }
            
            with open(self.output, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log(f"Results saved to {self.output}", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to save results: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description='Subdomain Takeover Scanner - Detect vulnerable subdomain configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive scan only
  python subdomain_takeover_scanner.py -d example.com
  
  # With wordlist
  python subdomain_takeover_scanner.py -d example.com -w wordlist.txt
  
  # With custom threads and timeout
  python subdomain_takeover_scanner.py -d example.com -w wordlist.txt -t 20 --timeout 10
  
  # Save results to JSON
  python subdomain_takeover_scanner.py -d example.com -o results.json -v
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for subdomain enumeration')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create scanner instance and run
    scanner = SubdomainTakeoverScanner(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        output=args.output
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    main()
