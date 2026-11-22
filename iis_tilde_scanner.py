#!/usr/bin/env python3
"""
IIS Tilde (~) Vulnerability Scanner
Professional bug bounty tool for detecting IIS 8.3 short name enumeration
"""

import requests
import time
import argparse
import sys
import statistics
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

init(autoreset=True)

class IISTildeScanner:
    def __init__(self, target_url, threads=5, timeout=10, headers=None, cookies=None):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        
        if headers:
            self.session.headers.update(headers)
        
        if cookies:
            self.session.cookies.update(cookies)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        
        self.vulnerable = False
        self.findings = []

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║           IIS Tilde (~) Vulnerability Scanner                 ║
║                  Professional Bug Bounty Tool                  ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def log(self, message, level="INFO"):
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        prefix = f"[{level}]"
        print(f"{color}{prefix:<10}{Style.RESET_ALL} {message}")

    def test_endpoint_exists(self, path="/"):
        try:
            url = urljoin(self.target_url, path)
            self.log(f"Testing endpoint: {url}")
            resp = self.session.get(url, timeout=self.timeout)
            self.log(f"Status: {resp.status_code} | Server: {resp.headers.get('Server', 'Unknown')}", "INFO")
            return True, resp
        except Exception as e:
            self.log(f"Endpoint unreachable: {str(e)}", "ERROR")
            return False, None

    def detect_server_type(self):
        self.log("Detecting server type...")
        reachable, resp = self.test_endpoint_exists()
        
        if not reachable:
            return False
        
        server_header = resp.headers.get('Server', '').lower()
        powered_by = resp.headers.get('X-Powered-By', '').lower()
        
        is_iis = any([
            'iis' in server_header,
            'microsoft' in server_header,
            'asp.net' in powered_by,
            'x-aspnet-version' in [h.lower() for h in resp.headers.keys()]
        ])
        
        if is_iis:
            self.log(f"IIS Server detected! (Server: {server_header})", "SUCCESS")
        else:
            self.log(f"Non-IIS server detected: {server_header}", "WARNING")
            self.log("Target may not be vulnerable to IIS Tilde attack", "WARNING")
        
        via = resp.headers.get('Via', '').lower()
        cf_ray = resp.headers.get('CF-Ray', '')
        x_cache = resp.headers.get('X-Cache', '').lower()
        
        if any([via and 'cloudfront' in via, cf_ray, 'cloudflare' in via]):
            self.log("CDN detected (CloudFront/Cloudflare) - May block tilde requests", "WARNING")
        
        return is_iis

    def test_basic_tilde_vulnerability(self, base_path="/"):
        self.log(f"Testing basic tilde vulnerability on: {base_path}")
        
        test_cases = [
            ("Valid tilde pattern", f"{base_path}*~1*/.aspx", "404"),
            ("Invalid pattern control", f"{base_path}xyz123~1*/.aspx", "400"),
            ("Asterisk only", f"{base_path}*", None),
            ("Double tilde", f"{base_path}*~~1*/.aspx", "400"),
        ]
        
        results = {}
        
        for desc, path, expected in test_cases:
            try:
                url = urljoin(self.target_url, path)
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                results[desc] = {
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'time': resp.elapsed.total_seconds() * 1000
                }
                
                self.log(f"{desc}: Status={resp.status_code}, Length={len(resp.content)}", "INFO")
                
            except Exception as e:
                self.log(f"Error testing {desc}: {str(e)}", "ERROR")
                results[desc] = None
        
        if results.get("Valid tilde pattern") and results.get("Invalid pattern control"):
            valid = results["Valid tilde pattern"]
            invalid = results["Invalid pattern control"]
            
            if valid['status'] != invalid['status']:
                self.log(f"VULNERABILITY DETECTED: Status code difference!", "VULN")
                self.log(f"Valid pattern: {valid['status']}, Invalid pattern: {invalid['status']}", "VULN")
                self.vulnerable = True
                return True
            
            time_diff = abs(valid['time'] - invalid['time'])
            if time_diff > 50:
                self.log(f"POTENTIAL VULNERABILITY: Timing difference detected ({time_diff:.2f}ms)", "WARNING")
                self.log(f"Valid: {valid['time']:.2f}ms, Invalid: {invalid['time']:.2f}ms", "WARNING")
                return True
            
            if valid['length'] != invalid['length']:
                self.log(f"POTENTIAL VULNERABILITY: Content length difference detected", "WARNING")
                self.log(f"Valid: {valid['length']} bytes, Invalid: {invalid['length']} bytes", "WARNING")
                return True
        
        self.log("No clear vulnerability indicators detected", "INFO")
        return False

    def test_common_paths(self):
        common_paths = [
            "/",
            "/admin/",
            "/uploads/",
            "/content/",
            "/static/",
            "/images/",
            "/files/",
            "/documents/",
            "/resources/",
            "/scripts/",
            "/styles/",
            "/css/",
            "/js/",
            "/backup/",
            "/old/",
            "/temp/",
            "/api/",
        ]
        
        self.log("Testing common paths for vulnerability...", "INFO")
        vulnerable_paths = []
        
        for path in common_paths:
            self.log(f"Testing path: {path}", "INFO")
            if self.test_basic_tilde_vulnerability(path):
                vulnerable_paths.append(path)
                self.log(f"Vulnerable path found: {path}", "VULN")
        
        return vulnerable_paths

    def test_extensions(self, base_path="/"):
        extensions = [
            ".aspx", ".asp", ".config", ".cs", ".ashx", 
            ".asmx", ".dll", ".txt", ".xml", ".pdf",
            ".doc", ".xls", ".zip", ".rar", ".bak"
        ]
        
        self.log(f"Testing extensions on {base_path}", "INFO")
        vulnerable_exts = []
        
        for ext in extensions:
            test_path = f"{base_path}*~1*/{ext}"
            url = urljoin(self.target_url, test_path)
            
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 404:
                    vulnerable_exts.append(ext)
                    self.log(f"Extension {ext} may be enumerable", "WARNING")
            except:
                continue
        
        return vulnerable_exts

    def generate_report(self, vulnerable_paths, vulnerable_exts):
        report = f"""
{Fore.CYAN}{'='*70}
SCAN REPORT
{'='*70}{Style.RESET_ALL}

Target: {self.target_url}
Date: {time.strftime('%Y-%m-%d %H:%M:%S')}

"""
        if self.vulnerable:
            report += f"{Fore.RED}[!] VULNERABILITY CONFIRMED{Style.RESET_ALL}\n\n"
            report += "The target is vulnerable to IIS Tilde (~) short name enumeration.\n\n"
            
            if vulnerable_paths:
                report += f"{Fore.YELLOW}Vulnerable Paths:{Style.RESET_ALL}\n"
                for path in vulnerable_paths:
                    report += f"  - {path}\n"
                report += "\n"
            
            if vulnerable_exts:
                report += f"{Fore.YELLOW}Enumerable Extensions:{Style.RESET_ALL}\n"
                for ext in vulnerable_exts:
                    report += f"  - {ext}\n"
                report += "\n"
            
            report += f"{Fore.YELLOW}Remediation:{Style.RESET_ALL}\n"
            report += "1. Disable 8.3 file name creation on the server\n"
            report += "2. Remove existing 8.3 names from the filesystem\n"
            report += "3. Upgrade to latest .NET Framework and IIS version\n"
            report += "4. Use URL rewrite rules to block tilde characters\n\n"
            
            report += f"{Fore.YELLOW}CVSS Score:{Style.RESET_ALL} Medium (5.3)\n"
            report += f"{Fore.YELLOW}CWE:{Style.RESET_ALL} CWE-200 (Information Exposure)\n\n"
            
        else:
            report += f"{Fore.GREEN}[✓] NO VULNERABILITY DETECTED{Style.RESET_ALL}\n\n"
            report += "The target does not appear to be vulnerable to IIS Tilde attacks.\n"
            report += "This could be because:\n"
            report += "  - Server is not running IIS\n"
            report += "  - 8.3 naming is disabled\n"
            report += "  - WAF/CDN is blocking tilde requests\n"
            report += "  - Application-level authentication blocks enumeration\n\n"
        
        report += f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n"
        
        print(report)
        
        filename = f"iis_tilde_scan_{urlparse(self.target_url).netloc}_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            import re
            clean_report = re.sub(r'\x1b\[[0-9;]*m', '', report)
            f.write(clean_report)
        
        self.log(f"Report saved to: {filename}", "SUCCESS")

    def run_full_scan(self):
        self.print_banner()
        
        self.log(f"Starting scan on: {self.target_url}", "INFO")
        self.log(f"Threads: {self.threads} | Timeout: {self.timeout}s", "INFO")
        print()
        
        self.detect_server_type()
        print()
        
        self.log("Phase 1: Basic vulnerability detection", "INFO")
        self.test_basic_tilde_vulnerability()
        print()
        
        self.log("Phase 2: Testing common paths", "INFO")
        vulnerable_paths = self.test_common_paths()
        print()
        
        self.log("Phase 3: Testing file extensions", "INFO")
        vulnerable_exts = self.test_extensions()
        print()
        
        self.generate_report(vulnerable_paths, vulnerable_exts)
        
        return self.vulnerable


def parse_cookies(cookie_string):
    cookies = {}
    if cookie_string:
        for item in cookie_string.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                cookies[key] = value
    return cookies


def parse_headers(header_list):
    headers = {}
    if header_list:
        for item in header_list:
            if ':' in item:
                key, value = item.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def main():
    parser = argparse.ArgumentParser(
        description='IIS Tilde (~) Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-H', '--header', action='append', help='Custom header')
    parser.add_argument('-c', '--cookie', help='Cookie string')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    headers = parse_headers(args.header)
    cookies = parse_cookies(args.cookie)
    
    scanner = IISTildeScanner(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        headers=headers,
        cookies=cookies
    )
    
    try:
        is_vulnerable = scanner.run_full_scan()
        sys.exit(0 if not is_vulnerable else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
