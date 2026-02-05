![cover-image](https://github.com/0xS4r4n9/SubHawk/blob/main/Subhawk.png)

# Subdomain Takeover Scanner

A comprehensive Python tool for detecting subdomain takeover vulnerabilities across various cloud platforms and services.

## Features

✅ **Passive Subdomain Enumeration**
- Certificate Transparency (crt.sh) integration
- Discovers subdomains without active scanning

✅ **Active Subdomain Enumeration**
- Wordlist-based subdomain discovery
- Multi-threaded scanning for speed
- Customizable wordlists

✅ **Vulnerability Detection**
- 18+ service fingerprints (AWS S3, GitHub Pages, Heroku, Azure, etc.)
- CNAME validation
- HTTP response analysis
- Automatic vulnerability identification

✅ **Comprehensive Reporting**
- Color-coded terminal output
- JSON export capability
- Detailed evidence collection
- Service identification

## Supported Services

The scanner detects takeover vulnerabilities for:

- **Cloud Storage**: AWS S3, Azure Storage
- **Hosting Platforms**: GitHub Pages, Heroku, Netlify, Surge.sh
- **E-commerce**: Shopify
- **Blogging**: Tumblr, WordPress, Ghost
- **Support**: Zendesk, UserVoice, Statuspage
- **CDN**: Fastly, CloudFront
- **Development**: Bitbucket, Pantheon
- **Marketing**: Unbounce, Cargo
- **And more...**

## Installation

### Requirements

```bash
pip install dnspython requests
```

### Python Version
- Python 3.6+

## Usage

### Basic Usage (Passive Scan Only)

```bash
python subdomain_takeover_scanner.py -d example.com
```

This will:
- Query Certificate Transparency logs
- Discover subdomains passively
- Check for takeover vulnerabilities

### With Wordlist (Active + Passive)

```bash
python subdomain_takeover_scanner.py -d example.com -w subdomain_wordlist.txt
```

### Advanced Options

```bash
# Custom threads and timeout
python subdomain_takeover_scanner.py -d example.com -w wordlist.txt -t 20 --timeout 10

# Verbose mode with JSON output
python subdomain_takeover_scanner.py -d example.com -w wordlist.txt -v -o results.json

# Maximum speed configuration
python subdomain_takeover_scanner.py -d example.com -w wordlist.txt -t 50 --timeout 3
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain` | Target domain (required) | - |
| `-w, --wordlist` | Wordlist file for subdomain enumeration | None |
| `-t, --threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 5 |
| `-v, --verbose` | Enable verbose output | False |
| `-o, --output` | Output file (JSON format) | None |

## How It Works

### 1. Subdomain Discovery
- **Passive**: Queries Certificate Transparency logs via crt.sh
- **Active**: DNS resolution using wordlist

### 2. CNAME Resolution
- Retrieves CNAME records for each subdomain
- Identifies third-party service pointers

### 3. Fingerprinting
- Matches CNAME patterns against known services
- Analyzes HTTP responses for error signatures
- Combines both for accurate detection

### 4. Vulnerability Assessment
- Confirms service identification
- Validates takeover possibility
- Collects evidence

## Understanding the Results

### Vulnerable Finding Example

```
[!] subdomain.example.com
    Service: GitHub Pages
    CNAME: example.github.io
    └─ CNAME points to: example.github.io
    └─ Service identified: GitHub Pages
    └─ HTTP Status: 404
```

This indicates:
- The subdomain points to GitHub Pages
- The repository doesn't exist or isn't configured
- **Action Required**: Register the GitHub repository or remove the DNS record

### Output Format

The scanner provides:
1. **Real-time colored terminal output**
2. **Summary statistics**
3. **Detailed vulnerability information**
4. **Optional JSON export for automation**

## Sample JSON Output

```json
{
  "scan_info": {
    "domain": "example.com",
    "timestamp": "2024-02-04T10:30:00",
    "total_subdomains": 45,
    "vulnerable_count": 2
  },
  "subdomains": ["www.example.com", "blog.example.com", ...],
  "vulnerable": [
    {
      "subdomain": "old-blog.example.com",
      "vulnerable": true,
      "service": "GitHub Pages",
      "cname": ["example.github.io"],
      "evidence": [
        "CNAME points to: example.github.io",
        "Service identified: GitHub Pages",
        "HTTP Status: 404"
      ]
    }
  ]
}
```

## Wordlist Recommendations

### Included Wordlist
The `subdomain_wordlist.txt` contains 100+ common subdomain names.

### External Wordlists
For comprehensive scanning, use:
- **SecLists**: `Discovery/DNS/subdomains-top1million-*.txt`
- **Assetnote**: `best-dns-wordlist.txt`
- **JHaddix**: `all.txt`

```bash
# Example with large wordlist
python subdomain_takeover_scanner.py -d example.com -w /path/to/large-wordlist.txt -t 50
```

## Remediation

If vulnerabilities are found:

1. **Option 1 - Claim the Service**
   - Register/configure the service pointed to by CNAME
   - Verify ownership

2. **Option 2 - Remove DNS Record**
   - Delete the CNAME record
   - Prevents potential takeover

3. **Option 3 - Update CNAME**
   - Point to a controlled resource
   - Ensure proper configuration

## Best Practices

### Bug Bounty Hunting
```bash
# Comprehensive scan
python subdomain_takeover_scanner.py -d target.com -w comprehensive-wordlist.txt -t 30 -v -o target_results.json
```

### Security Audit
```bash
# Company domain audit
python subdomain_takeover_scanner.py -d company.com -w enterprise-wordlist.txt -o audit_$(date +%Y%m%d).json
```

### Responsible Disclosure
- Never take over subdomains you don't own
- Report findings to the domain owner or bug bounty program
- Document evidence before removal

## Performance Tips

1. **Optimize Threads**: Start with 10-20, increase gradually
2. **Adjust Timeout**: Lower for faster scanning, higher for reliability
3. **Use Quality Wordlists**: Focused wordlists are more efficient
4. **Monitor Resources**: Watch network and CPU usage

## Limitations

- **Rate Limiting**: Some services may rate-limit DNS or HTTP requests
- **False Positives**: Manual verification recommended
- **Service Updates**: Fingerprints may need updates as services change
- **Network Restrictions**: Requires outbound DNS and HTTP access

## Troubleshooting

### No Subdomains Found
```bash
# Try with wordlist
python subdomain_takeover_scanner.py -d example.com -w subdomain_wordlist.txt -v
```

### DNS Resolution Errors
- Check DNS server configuration
- Try increasing timeout: `--timeout 10`
- Reduce thread count: `-t 5`

### SSL/Certificate Errors
- The script automatically handles SSL verification
- Uses both HTTPS and HTTP protocols

## Security Considerations

⚠️ **Legal Notice**: Only scan domains you own or have explicit permission to test.

- Use responsibly and ethically
- Respect rate limits
- Follow bug bounty program rules
- Document all findings properly

## Contributing

To add new service fingerprints, update the `FINGERPRINTS` dictionary:

```python
'Service Name': {
    'cname': ['service.provider.com'],
    'http': ['Error message pattern'],
    'vulnerable': True
}
```

## License

This tool is provided for educational and authorized security testing purposes only.

## Support

For issues or questions:
- Review the documentation
- Check verbose output: `-v`
- Verify DNS and network connectivity

## Version History

- **v1.0** - Initial release with 18 service fingerprints
  - Passive enumeration via crt.sh
  - Multi-threaded scanning
  - JSON export
  - Colored terminal output

---

**Happy (Ethical) Hunting! 🎯🔒**
