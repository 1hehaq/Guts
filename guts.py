import os
import re
import ssl
import socket
import json
import argparse
import requests
import dns.resolver
import whois
import shodan
import nmap
import tldextract
import subprocess
from bs4 import BeautifulSoup
from ipwhois import IPWhois
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from configparser import ConfigParser

# Configuration file
CONFIG_FILE = 'config.ini'

def load_config():
    config = ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        config['API_KEYS'] = {
            'shodan_api_key': '',
            'virustotal_api_key': ''
        }
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    else:
        config.read(CONFIG_FILE)
    return config

def save_config(config):
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def get_api_keys():
    config = load_config()
    shodan_api_key = config['API_KEYS']['shodan_api_key']
    virustotal_api_key = config['API_KEYS']['virustotal_api_key']
    
    if not shodan_api_key:
        shodan_api_key = input("Enter your Shodan API key: ")
        config['API_KEYS']['shodan_api_key'] = shodan_api_key
    if not virustotal_api_key:
        virustotal_api_key = input("Enter your VirusTotal API key: ")
        config['API_KEYS']['virustotal_api_key'] = virustotal_api_key

    save_config(config)
    return shodan_api_key, virustotal_api_key

def create_report(findings, target_url):
    output_dir = "reports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    report_path = os.path.join(output_dir, "recon_report.pdf")
    c = canvas.Canvas(report_path, pagesize=letter)
    width, height = letter
    c.drawString(100, height - 100, "Reconnaissance Report")
    c.drawString(100, height - 120, f"Target: {target_url}")
    c.drawString(100, height - 140, "Findings:")

    y = height - 160
    for finding in findings:
        c.drawString(100, y, f"- {finding}")
        y -= 20

    c.save()
    print(f"Report generated: {report_path}")

def web_scrape(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'lxml')
        return soup
    except requests.RequestException as e:
        print(f"Error during web scraping: {e}")
        return None

def dns_enum(domain):
    result = []
    for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for answer in answers:
                result.append(f"{record_type}: {answer.to_text()}")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.DNSException as e:
            print(f"DNS error for {record_type}: {e}")
    return result

def subdomain_enum(domain):
    try:
        output = subprocess.check_output(['subfinder', '-d', domain, '-silent'], text=True)
        subdomains = output.split()
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"Subfinder error: {e}")
        return []

def port_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-1024', '-v')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(f"Port {port}/{proto} is open on {host}")
        return open_ports
    except nmap.PortScannerError as e:
        print(f"Nmap error: {e}")
        return []

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        print(f"Whois lookup error: {e}")
        return None

def ip_geolocation(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res
    except Exception as e:
        print(f"IP geolocation error: {e}")
        return None

def shodan_scan(ip, api_key):
    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        print(f"Shodan error: {e}")
        return None

def get_http_headers(url):
    try:
        response = requests.head(url)
        response.raise_for_status()
        return response.headers
    except requests.RequestException as e:
        print(f"HTTP headers error: {e}")
        return None

def ssl_cert_info(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return cert
    except Exception as e:
        print(f"SSL certificate error: {e}")
        return None

def dns_zone_transfer(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            try:
                ns_addr = dns.resolver.resolve(ns.target, 'A')[0].address
                zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain))
                return zone.to_text()
            except Exception:
                continue
    except dns.resolver.DNSException as e:
        print(f"DNS zone transfer error: {e}")
    return "Zone transfer not possible"

def email_harvest(domain):
    try:
        emails = set()
        response = requests.get(domain)
        matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
        emails.update(matches)
        return emails
    except requests.RequestException as e:
        print(f"Email harvesting error: {e}")
        return set()

def reverse_dns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except socket.herror:
        return None

def social_media_enum(domain):
    profiles = []
    social_media_sites = ['twitter.com', 'facebook.com', 'linkedin.com']
    for site in social_media_sites:
        url = f"https://{site}/{domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                profiles.append(url)
        except requests.RequestException:
            continue
    return profiles

def virustotal_scan(domain, api_key):
    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}
        response = requests.get(url, params=params)
        return response.json()
    except requests.RequestException as e:
        print(f"VirusTotal error: {e}")
        return None

def main(target_url):
    shodan_api_key, virustotal_api_key = get_api_keys()
    findings = []

    # Step 1: Web scraping
    print("[*] Starting web scraping...")
    soup = web_scrape(target_url)
    if soup and soup.title:
        findings.append(f"Title: {soup.title.string}")
    print("[*] Web scraping completed.")

    # Step 2: Web crawling - Removed

    # Step 3: DNS enumeration
    print("[*] Starting DNS enumeration...")
    domain = tldextract.extract(target_url).registered_domain
    dns_info = dns_enum(domain)
    findings.extend(dns_info)
    print("[*] DNS enumeration completed.")

    # Step 4: Subdomain enumeration
    print("[*] Starting subdomain enumeration...")
    subdomains = subdomain_enum(domain)
    findings.append(f"Discovered subdomains: {', '.join(subdomains)}")
    print("[*] Subdomain enumeration completed.")

    # Step 5: Port scanning
    print("[*] Starting port scanning...")
    ports = port_scan(target_url)
    findings.extend(ports)
    print("[*] Port scanning completed.")

    # Step 6: Whois lookup
    print("[*] Starting whois lookup...")
    whois_info = whois_lookup(domain)
    if whois_info:
        findings.append(f"Whois info: {whois_info}")
    print("[*] Whois lookup completed.")

    # Step 7: IP geolocation
    ip_address = requests.get(f'https://api.ipify.org?format=json').json()['ip']
    print("[*] Starting IP geolocation...")
    geo_info = ip_geolocation(ip_address)
    if geo_info:
        findings.append(f"IP Geolocation info: {geo_info}")
    print("[*] IP geolocation completed.")

    # Step 8: Shodan scanning
    print("[*] Starting Shodan scan...")
    shodan_info = shodan_scan(ip_address, shodan_api_key)
    if shodan_info:
        findings.append(f"Shodan info: {shodan_info}")
    print("[*] Shodan scan completed.")

    # Step 9: HTTP headers collection
    print("[*] Starting HTTP headers collection...")
    headers = get_http_headers(target_url)
    if headers:
        findings.append(f"HTTP Headers: {headers}")
    print("[*] HTTP headers collection completed.")

    # Step 10: SSL certificate information
    print("[*] Starting SSL certificate information retrieval...")
    ssl_info = ssl_cert_info(domain)
    if ssl_info:
        findings.append(f"SSL Certificate info: {ssl_info}")
    print("[*] SSL certificate information retrieval completed.")

    # Step 11: DNS zone transfer
    print("[*] Starting DNS zone transfer...")
    zone_transfer_info = dns_zone_transfer(domain)
    findings.append(f"DNS Zone Transfer info: {zone_transfer_info}")
    print("[*] DNS zone transfer completed.")

    # Step 12: Email harvesting
    print("[*] Starting email harvesting...")
    emails = email_harvest(target_url)
    findings.append(f"Harvested emails: {', '.join(emails)}")
    print("[*] Email harvesting completed.")

    # Step 13: Reverse DNS lookup
    print("[*] Starting reverse DNS lookup...")
    reverse_dns_info = reverse_dns(ip_address)
    if reverse_dns_info:
        findings.append(f"Reverse DNS info: {reverse_dns_info}")
    print("[*] Reverse DNS lookup completed.")

    # Step 14: Social Media Enumeration
    print("[*] Starting social media enumeration...")
    social_media_profiles = social_media_enum(domain)
    findings.append(f"Social media profiles: {social_media_profiles}")
    print("[*] Social media enumeration completed.")

    # Step 15: VirusTotal scanning
    print("[*] Starting VirusTotal scan...")
    virustotal_info = virustotal_scan(domain, virustotal_api_key)
    if virustotal_info:
        findings.append(f"VirusTotal scan info: {virustotal_info}")
    print("[*] VirusTotal scan completed.")

    # Step 16: Creating the report
    print("[*] Generating report...")
    create_report(findings, target_url)
    print("[*] Report generation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconnaissance Automation Tool")
    parser.add_argument("target_url", help="Target URL for reconnaissance")

    args = parser.parse_args()
    main(args.target_url)
