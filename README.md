<div align="center">
<h1>How it Works</h1>

    Input Domain
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │             🛠️  Reconnaissance Automation Tool  🛠️            │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │             🌐  Web Scraping & DNS Enumeration  🌐            │
       │          (BeautifulSoup, dns.resolver, tldextract)             │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │               🔍  Subdomain Enumeration  🔍                   │
       │   (Subfinder, Assetfinder, Amass - Bringing Domains to Light)  │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │               🕵️  Port Scanning & WHOIS Lookup  🕵️            │
       │     (nmap, whois, ipwhois, socket - Unraveling Mysteries)      │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │               🌎  IP Geolocation  🌎                          │
       │  (IPWhois, RDAP API, Shodan - Mapping the Digital Terrain)     │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │           📝  HTTP Headers Collection  📝                     │
       │          (requests, response.headers - Peek Behind the Curtain)│
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │           🔒  SSL Certificate Information  🔒                 │
       │     (ssl, socket, cert - Decrypting the Digital Enigma)        │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │                🌀 DNS Zone Transfer 🌀                        │
       │     (dns.zone.from_xfr, dns.query.xfr - Unveiling Secrets)     │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │                  📧 Email Harvesting 📧                       │
       │      (re, requests, re.findall - Harvesting Digital Bounty)    │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │                🔍 Reverse DNS Lookup 🔍                       │
       │       (socket, socket.gethostbyaddr - Seeking Identity)        │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │             🌟 Social Media Enumeration 🌟                    │
       │     (requests, response.status_code - Exploring Networks)      │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │                ☣️ VirusTotal Scanning ☣️                      │
       │      (requests, params, response.json - Detecting Threats)     │
       └────────────────────────────────────────────────────────────────┘
         │
         ▼
       ┌────────────────────────────────────────────────────────────────┐
       │                      📊 Output 📊                             │
       │                  (Generated Recon Report)                      │
       └────────────────────────────────────────────────────────────────┘









# Guts: Reconnaissance Automation Tool

Guts is a powerful reconnaissance automation tool. It equips cybersecurity enthusiasts and penetration testers with a comprehensive set of tools to gather intelligence and unveil hidden truths in the digital landscape.
</div>

## Features

- **Web Scraping:** Extract valuable information from web pages effortlessly.
- **DNS Enumeration:** Discover DNS records such as A, AAAA, MX, NS, TXT, and CNAME records for a target domain.
- **Subdomain Enumeration:** Enumerate subdomains associated with the target domain.
- **Port Scanning:** Scan target hosts for open ports and identify potential vulnerabilities.
- **WHOIS Lookup:** Retrieve WHOIS information for a domain to gather details about its registration.
- **IP Geolocation:** Obtain geolocation information for IP addresses to pinpoint their physical location.
- **Shodan Scanning:** Conduct Shodan scans to gather intelligence on devices connected to the internet.
- **HTTP Headers Collection:** Retrieve HTTP headers for a target URL to analyze server configurations.
- **SSL Certificate Information:** Obtain SSL certificate details for a domain to assess its security posture.
- **DNS Zone Transfer:** Attempt DNS zone transfers to gather comprehensive information about a DNS zone.
- **Email Harvesting:** Harvest email addresses from web pages for further analysis.
- **Reverse DNS Lookup:** Perform reverse DNS lookups to map IP addresses to hostnames.
- **Social Media Enumeration:** Discover social media profiles associated with the target domain.
- **VirusTotal Scanning:** Conduct VirusTotal scans to assess the reputation of a domain.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/1hehaq/Guts.git
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python guts.py http://example.com
```

Replace `http://example.com` with the URL of the target you want to perform reconnaissance on.

## Configuration

Before using the tool, make sure to configure your API keys for Shodan and VirusTotal in the `config.ini` file.

```ini
[API_KEYS]
shodan_api_key = your_shodan_api_key
virustotal_api_key = your_virustotal_api_key
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request to enhance the tool's functionality or fix any bugs.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
