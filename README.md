# CyberSentry Pro - Automated Penetration Testing Tool

> Comprehensive ethical hacking toolkit for bug bounty hunters

## Features
- 5-level penetration testing intensity
- OWASP Top 10 vulnerability scanning
- Automated reconnaissance
- Exploit verification
- PDF/HTML/TXT reporting
- Legal compliance safeguards

## Installation
```bash
git clone https://github.com/yourusername/CyberSentryPro.git
cd CyberSentryPro
pip install -r requirements.txt
```

## Usage
```bash
# Basic scan (Level 3)
python cybersentry.py -i 192.168.1.100 -d example.com -l 3

# Full penetration test (Level 5 - requires permission)
python cybersentry.py -i 10.0.0.1 -d internal-app.com -l 5

# Generate HTML report
python cybersentry.py -i 203.0.113.5 -d test.site -o html
```

## Legal Disclaimer
```legal
CyberSentry Pro must only be used on systems you own or have explicit written permission to test. 
Unauthorized access is illegal. By using this tool, you agree to use it ethically and legally.
```

## Contribution
Submit issues and PRs for:
- New vulnerability checks
- API integrations
- Report template improvements
- Performance optimizations
