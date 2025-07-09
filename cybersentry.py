#!/usr/bin/env python3
"""
CyberSentry Pro - Comprehensive Penetration Testing Framework
Author: AI Security Assistant
Version: 1.0
"""

import argparse
import os
import sys
import time
import requests
import nmap
import dns.resolver
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from bs4 import BeautifulSoup
import configparser

# Configuration
DISCLAIMER = """
***********************************************************************
* CyberSentry Pro - Penetration Testing Tool                          *
*                                                                     *
* LEGAL DISCLAIMER:                                                   *
* This tool must only be used on systems you own or have explicit      *
* written permission to test. Unauthorized access is illegal.         *
*                                                                     *
* By using this tool, you agree to use it ethically and legally.      *
***********************************************************************
"""

# Path to wordlists and payloads
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_DIR = os.path.join(BASE_DIR, "config", "wordlists")
PAYLOADS_FILE = os.path.join(BASE_DIR, "config", "payloads.txt")
API_KEYS_FILE = os.path.join(BASE_DIR, "config", "api_keys.conf")

VULN_DB = {
    "SQLi": {
        "severity": "Critical",
        "description": "SQL Injection vulnerability allows attackers to manipulate database queries",
        "remediation": "Use parameterized queries, input validation, and ORM frameworks",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "XSS": {
        "severity": "High",
        "description": "Cross-site scripting allows execution of malicious scripts in user's browser",
        "remediation": "Implement output encoding, Content Security Policy (CSP), and input sanitization",
        "reference": "https://owasp.org/www-community/attacks/xss/"
    },
    "Directory Traversal": {
        "severity": "High",
        "description": "Directory traversal vulnerability allows reading arbitrary files on the server",
        "remediation": "Validate user input, use chroot jails, and avoid passing user input to filesystem APIs",
        "reference": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    # Add more vulnerability templates
}

class CyberSentry:
    def __init__(self, target_ip, target_domain, level, output_format="pdf"):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.level = level
        self.output_format = output_format
        self.results = {
            "recon": {},
            "vulnerabilities": [],
            "pentest": {}
        }
        self.start_time = time.time()
        self.api_keys = self.load_api_keys()
        
        print(DISCLAIMER)
        self.confirm_permission()
        
    def load_api_keys(self):
        """Load API keys from config file"""
        config = configparser.ConfigParser()
        if os.path.exists(API_KEYS_FILE):
            config.read(API_KEYS_FILE)
            return config
        return None
        
    def confirm_permission(self):
        """Verify user has proper authorization"""
        if self.level >= 4:
            response = input(f"\n[!] WARNING: Level {self.level} testing is intrusive. "
                             "Do you have EXPLICIT permission? (yes/NO): ")
            if response.lower() != "yes":
                print("[!] Aborting - Permission not confirmed")
                sys.exit(1)
                
        print(f"\n[+] Starting CyberSentry Pro against {self.target_domain} ({self.target_ip}) at Level {self.level}")

    def run(self):
        """Execute penetration test based on level"""
        # Level 1: Passive Reconnaissance
        if self.level >= 1:
            print("\n[=== PHASE 1: PASSIVE RECONNAISSANCE ===]")
            self.passive_recon()
        
        # Level 2: Active Scanning
        if self.level >= 2:
            print("\n[=== PHASE 2: ACTIVE SCANNING ===]")
            self.active_scanning()
        
        # Level 3: Vulnerability Assessment
        if self.level >= 3:
            print("\n[=== PHASE 3: VULNERABILITY ASSESSMENT ===]")
            self.vulnerability_assessment()
        
        # Level 4: Authentication Testing
        if self.level >= 4:
            print("\n[=== PHASE 4: AUTHENTICATION TESTING ===]")
            self.authentication_testing()
        
        # Level 5: Advanced Exploitation
        if self.level >= 5:
            print("\n[=== PHASE 5: ADVANCED EXPLOITATION ===]")
            self.advanced_exploitation()
        
        # Generate report
        self.generate_report()
        print(f"\n[+] Scan completed in {time.time() - self.start_time:.2f} seconds")

    def passive_recon(self):
        """Passive reconnaissance methods"""
        # WHOIS lookup
        try:
            import whois
            domain_info = whois.whois(self.target_domain)
            self.results["recon"]["whois"] = {
                "registrar": domain_info.registrar,
                "creation_date": str(domain_info.creation_date),
                "expiration_date": str(domain_info.expiration_date)
            }
            print("[+] WHOIS information gathered")
        except ImportError:
            print("[-] Install python-whois: pip install python-whois")
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {str(e)}")
        
        # DNS reconnaissance
        try:
            resolver = dns.resolver.Resolver()
            records = {}
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = resolver.resolve(self.target_domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except dns.resolver.NoAnswer:
                    pass
            self.results["recon"]["dns"] = records
            print("[+] DNS records enumerated")
        except Exception as e:
            print(f"[-] DNS enumeration failed: {str(e)}")
        
        # SSL/TLS information
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target_domain) as s:
                s.connect((self.target_domain, 443))
                cert = s.getpeercert()
                self.results["recon"]["ssl"] = {
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "expires": cert["notAfter"],
                    "subject": dict(x[0] for x in cert["subject"])
                }
            print("[+] SSL certificate information gathered")
        except Exception as e:
            print(f"[-] SSL check failed: {str(e)}")
            
        # Shodan integration if API key available
        if self.api_keys and 'SHODAN' in self.api_keys and self.api_keys['SHODAN'].get('API_KEY'):
            try:
                import shodan
                api = shodan.Shodan(self.api_keys['SHODAN']['API_KEY'])
                host = api.host(self.target_ip)
                self.results["recon"]["shodan"] = {
                    "ports": host.get('ports', []),
                    "vulns": host.get('vulns', []),
                    "os": host.get('os', ''),
                    "hostnames": host.get('hostnames', [])
                }
                print("[+] Shodan information gathered")
            except ImportError:
                print("[-] Install shodan: pip install shodan")
            except Exception as e:
                print(f"[-] Shodan query failed: {str(e)}")

    def active_scanning(self):
        """Active scanning and enumeration"""
        # Port scanning with Nmap
        try:
            scanner = nmap.PortScanner()
            scanner.scan(self.target_ip, arguments=f"-sV -T4 --min-rate 1000")
            self.results["pentest"]["ports"] = {}
            
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        self.results["pentest"]["ports"][port] = {
                            "state": service["state"],
                            "service": service["name"],
                            "version": service["version"]
                        }
            print(f"[+] Port scan completed: {len(self.results['pentest']['ports'])} ports found")
        except Exception as e:
            print(f"[-] Nmap scan failed: {str(e)}")
        
        # Subdomain enumeration
        try:
            from tqdm import tqdm
            subdomains = []
            wordlist = os.path.join(WORDLIST_DIR, "subdomains.txt")
            
            if os.path.exists(wordlist):
                with open(wordlist, "r") as f:
                    sub_list = f.read().splitlines()
                
                for sub in tqdm(sub_list, desc="Subdomain enumeration"):
                    domain = f"{sub}.{self.target_domain}"
                    try:
                        requests.get(f"http://{domain}", timeout=2)
                        subdomains.append(domain)
                    except:
                        continue
            else:
                print(f"[-] Subdomain wordlist not found at {wordlist}")
            
            self.results["recon"]["subdomains"] = subdomains
            print(f"[+] Found {len(subdomains)} subdomains")
        except ImportError:
            print("[-] Install tqdm for progress bars: pip install tqdm")
        except Exception as e:
            print(f"[-] Subdomain enumeration failed: {str(e)}")
        
        # Technology stack detection
        try:
            headers = {"User-Agent": "CyberSentryPro/1.0"}
            response = requests.get(f"http://{self.target_domain}", headers=headers, timeout=10)
            tech_stack = {}
            
            # Server header
            if "Server" in response.headers:
                tech_stack["web_server"] = response.headers["Server"]
            
            # X-Powered-By header
            if "X-Powered-By" in response.headers:
                tech_stack["backend"] = response.headers["X-Powered-By"]
            
            # Framework detection via HTML patterns
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.find("meta", {"name": "generator", "content": "WordPress"}):
                tech_stack["cms"] = "WordPress"
            elif soup.find("meta", {"name": "generator", "content": "Joomla"}):
                tech_stack["cms"] = "Joomla"
            
            self.results["recon"]["tech_stack"] = tech_stack
            print("[+] Technology stack identified")
        except Exception as e:
            print(f"[-] Technology detection failed: {str(e)}")

    def vulnerability_assessment(self):
        """Detect common web vulnerabilities"""
        # Load payloads from file
        if os.path.exists(PAYLOADS_FILE):
            with open(PAYLOADS_FILE, "r") as f:
                payloads = [line.strip() for line in f.readlines()]
        else:
            print(f"[-] Payloads file not found at {PAYLOADS_FILE}, using default payloads")
            payloads = ["'", "\"", "' OR '1'='1", "' OR SLEEP(5)--"]
        
        # SQL Injection check
        test_url = f"http://{self.target_domain}/product?id=1"
        for payload in payloads:
            try:
                response = requests.get(test_url + payload, timeout=10)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    self.add_vulnerability("SQLi", test_url, payload)
                    print(f"[!] Potential SQLi found: {payload}")
                    break
            except:
                continue
        
        # XSS check
        test_url = f"http://{self.target_domain}/search?q="
        payload = "<script>alert('CyberSentry')</script>"
        try:
            response = requests.get(test_url + payload, timeout=10)
            if payload in response.text:
                self.add_vulnerability("XSS", test_url, payload)
                print(f"[!] Potential XSS found: {payload}")
        except:
            pass
        
        # Directory Traversal check
        test_url = f"http://{self.target_domain}/download?file="
        for payload in ["../../../../etc/passwd", "..././..././etc/passwd"]:
            try:
                response = requests.get(test_url + payload, timeout=10)
                if "root:" in response.text:
                    self.add_vulnerability("Directory Traversal", test_url, payload)
                    print(f"[!] Potential Directory Traversal found: {payload}")
                    break
            except:
                continue
        
        # Add more vulnerability checks here...

    def add_vulnerability(self, vuln_type, url, payload):
        """Add vulnerability to results"""
        if vuln_type in VULN_DB:
            self.results["vulnerabilities"].append({
                "type": vuln_type,
                "url": url,
                "payload": payload,
                "severity": VULN_DB[vuln_type]["severity"],
                "description": VULN_DB[vuln_type]["description"],
                "remediation": VULN_DB[vuln_type]["remediation"],
                "reference": VULN_DB[vuln_type]["reference"]
            })

    def authentication_testing(self):
        """Test authentication mechanisms"""
        # Session management test
        try:
            s = requests.Session()
            login_url = f"http://{self.target_domain}/login"
            login_data = {"username": "test", "password": "test"}
            
            # Initial request
            s.get(login_url)
            pre_auth_cookie = s.cookies.get_dict()
            
            # Login attempt
            s.post(login_url, data=login_data)
            post_auth_cookie = s.cookies.get_dict()
            
            # Check if session ID changed
            if "sessionid" in pre_auth_cookie and "sessionid" in post_auth_cookie:
                if pre_auth_cookie["sessionid"] == post_auth_cookie["sessionid"]:
                    self.results["pentest"]["session_fixation"] = True
                    print("[!] Session fixation vulnerability detected")
        except Exception as e:
            print(f"[-] Session testing failed: {str(e)}")
        
        # Brute-force resistance test
        try:
            from tqdm import tqdm
            login_url = f"http://{self.target_domain}/login"
            # Using a small list for demo; in real scenarios, use a comprehensive wordlist
            common_passwords = ["admin", "password", "123456", "qwerty"]
            
            for password in tqdm(common_passwords, desc="Brute-force test"):
                response = requests.post(login_url, data={
                    "username": "admin",
                    "password": password
                }, timeout=3)
                
                if "dashboard" in response.url or "welcome" in response.text:
                    self.results["pentest"]["weak_credentials"] = password
                    print(f"[!] Weak credentials found: admin/{password}")
                    break
        except:
            pass

    def advanced_exploitation(self):
        """Advanced exploitation techniques (Level 5)"""
        print("[*] Starting advanced exploitation phase")
        
        # Automatically exploit SQLi vulnerabilities
        for vuln in self.results["vulnerabilities"]:
            if vuln["type"] == "SQLi":
                try:
                    print(f"[*] Exploiting SQLi at {vuln['url']}")
                    # Use sqlmap API or similar for safe exploitation
                    # result = self.run_sqlmap(vuln['url'])
                    # self.results["pentest"]["exploitation"]["sqli"] = result
                except:
                    print("[-] SQLi exploitation failed")
        
        # Add other exploitation techniques here...

    def generate_report(self):
        """Generate report in specified format"""
        # Create reports directory if not exists
        reports_dir = os.path.join(BASE_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        filename = os.path.join(reports_dir, f"CyberSentry_Report_{self.target_domain}_{time.strftime('%Y%m%d_%H%M%S')}")
        
        if self.output_format == "pdf":
            self.generate_pdf_report(filename + ".pdf")
        elif self.output_format == "html":
            self.generate_html_report(filename + ".html")
        else:
            self.generate_text_report(filename + ".txt")
        
        print(f"[+] Report generated: {filename}.{self.output_format}")

    def generate_pdf_report(self, filename):
        """Generate PDF report"""
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title = Paragraph(f"CyberSentry Pro Report: {self.target_domain}", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Summary
        summary = Paragraph(f"<b>Scan Summary:</b><br/>"
                           f"Target: {self.target_domain} ({self.target_ip})<br/>"
                           f"Scan Level: {self.level}<br/>"
                           f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}<br/>"
                           f"Scan Duration: {time.time() - self.start_time:.2f} seconds",
                           styles["BodyText"])
        elements.append(summary)
        elements.append(Spacer(1, 24))
        
        # Vulnerabilities
        vuln_title = Paragraph("<b>Vulnerabilities Found:</b>", styles['Heading2'])
        elements.append(vuln_title)
        elements.append(Spacer(1, 12))
        
        for i, vuln in enumerate(self.results["vulnerabilities"]):
            vuln_text = (f"<b>{i+1}. {vuln['type']} ({vuln['severity']})</b><br/>"
                        f"URL: {vuln['url']}<br/>"
                        f"Payload: {vuln['payload']}<br/>"
                        f"Description: {vuln['description']}<br/>"
                        f"<b>Remediation:</b> {vuln['remediation']}<br/>"
                        f"Reference: <a href='{vuln['reference']}'>{vuln['reference']}</a>")
            elements.append(Paragraph(vuln_text, styles["BodyText"]))
            elements.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(elements)

    def generate_html_report(self, filename):
        """Generate HTML report"""
        with open(filename, "w") as f:
            f.write("<html><head><title>CyberSentry Pro Report</title></head><body>")
            f.write(f"<h1>CyberSentry Pro Report: {self.target_domain}</h1>")
            f.write("<h2>Scan Summary</h2>")
            f.write(f"<p>Target: {self.target_domain} ({self.target_ip})</p>")
            f.write(f"<p>Scan Level: {self.level}</p>")
            f.write(f"<p>Vulnerabilities Found: {len(self.results['vulnerabilities']}</p>")
            
            if self.results["vulnerabilities"]:
                f.write("<h2>Vulnerabilities</h2>")
                for i, vuln in enumerate(self.results["vulnerabilities"]):
                    f.write(f"<h3>{i+1}. {vuln['type']} ({vuln['severity']})</h3>")
                    f.write(f"<p><b>URL:</b> {vuln['url']}</p>")
                    f.write(f"<p><b>Payload:</b> {vuln['payload']}</p>")
                    f.write(f"<p><b>Description:</b> {vuln['description']}</p>")
                    f.write(f"<p><b>Remediation:</b> {vuln['remediation']}</p>")
                    f.write(f"<p><b>Reference:</b> <a href='{vuln['reference']}'>{vuln['reference']}</a></p>")
            
            f.write("</body></html>")

    def generate_text_report(self, filename):
        """Generate text report"""
        with open(filename, "w") as f:
            f.write(f"CyberSentry Pro Report: {self.target_domain}\n")
            f.write("="*50 + "\n\n")
            f.write(f"Target: {self.target_domain} ({self.target_ip})\n")
            f.write(f"Scan Level: {self.level}\n")
            f.write(f"Vulnerabilities Found: {len(self.results['vulnerabilities']}\n\n")
            
            if self.results["vulnerabilities"]:
                f.write("Vulnerabilities:\n")
                f.write("-"*50 + "\n")
                for i, vuln in enumerate(self.results["vulnerabilities"]):
                    f.write(f"{i+1}. {vuln['type']} ({vuln['severity']})\n")
                    f.write(f"   URL: {vuln['url']}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Description: {vuln['description']}\n")
                    f.write(f"   Remediation: {vuln['remediation']}\n")
                    f.write(f"   Reference: {vuln['reference']}\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentry Pro - Penetration Testing Framework")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-d", "--domain", required=True, help="Target domain name")
    parser.add_argument("-l", "--level", type=int, choices=range(1, 6), default=3,
                        help="Testing intensity level (1-5)")
    parser.add_argument("-o", "--output", choices=["pdf", "html", "txt"], default="pdf",
                        help="Output report format")
    
    args = parser.parse_args()
    
    scanner = CyberSentry(args.ip, args.domain, args.level, args.output)
    scanner.run()
