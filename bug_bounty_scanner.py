import requests
import threading
import argparse
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import time

# Setup logging
logging.basicConfig(filename='scan_report.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load payloads from files
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

sql_injection_payloads = load_payloads('sql_payloads.txt')
xss_payloads = load_payloads('xss_payloads.txt')
cmd_injection_payloads = load_payloads('cmd_payloads.txt')

# Function to test for SQL Injection
def test_sql_injection(url, payload, session):
    try:
        response = session.get(url, params={'q': payload}, timeout=10)
        if "sql syntax" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
            logging.info(f"Possible SQL Injection vulnerability found with payload: {payload}")
            print(f"Possible SQL Injection vulnerability found with payload: {payload}")
        else:
            logging.info(f"No SQL Injection vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing SQL Injection with payload {payload}: {e}")

# Function to test for XSS
def test_xss(url, payload, session):
    try:
        response = session.get(url, params={'q': payload}, timeout=10)
        if payload in response.text:
            logging.info(f"Possible XSS vulnerability found with payload: {payload}")
            print(f"Possible XSS vulnerability found with payload: {payload}")
        else:
            logging.info(f"No XSS vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing XSS with payload {payload}: {e}")

# Function to test for Command Injection
def test_cmd_injection(url, payload, session):
    try:
        response = session.get(url, params={'q': payload}, timeout=10)
        if "command not found" in response.text.lower() or "not recognized as an internal or external command" in response.text.lower():
            logging.info(f"Possible Command Injection vulnerability found with payload: {payload}")
            print(f"Possible Command Injection vulnerability found with payload: {payload}")
        else:
            logging.info(f"No Command Injection vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing Command Injection with payload {payload}: {e}")

# Function to test for CSRF protection
def test_csrf(url, session):
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                logging.info(f"Possible CSRF vulnerability found in form at {url}")
                print(f"Possible CSRF vulnerability found in form at {url}")
            else:
                logging.info(f"CSRF token found in form at {url}")
    except requests.RequestException as e:
        logging.error(f"Error testing CSRF protection on {url}: {e}")

# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Automated Bug Bounty Scanner')
    parser.add_argument('url', type=str, help='Target URL to scan')
    parser.add_argument('--login-url', type=str, help='Login URL for authenticated scans')
    parser.add_argument('--username', type=str, help='Username for login')
    parser.add_argument('--password', type=str, help='Password for login')
    parser.add_argument('--proxy', type=str, help='Proxy server to use for requests')
    parser.add_argument('--rate-limit', type=float, default=0, help='Rate limit for requests (seconds between requests)')
    return parser.parse_args()

# Function to validate URL
def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

# Function to login and create a session
def login(login_url, username, password, proxy):
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
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
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                url = urljoin(base_url, action)
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
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}
    if args.login_url and args.username and args.password:
        session = login(args.login_url, args.username, args.password, args.proxy)

    urls = discover_urls(target_url, session)
    urls.add(target_url)

    threads = []

    for url in urls:
        print(f"Testing for SQL Injection on {url}...")
        for payload in sql_injection_payloads:
            thread = threading.Thread(target=test_sql_injection, args=(url, payload, session))
            threads.append(thread)
            thread.start()
            time.sleep(args.rate_limit)

        print(f"Testing for XSS on {url}...")
        for payload in xss_payloads:
            thread = threading.Thread(target=test_xss, args=(url, payload, session))
            threads.append(thread)
            thread.start()
            time.sleep(args.rate_limit)

        print(f"Testing for Command Injection on {url}...")
        for payload in cmd_injection_payloads:
            thread = threading.Thread(target=test_cmd_injection, args=(url, payload, session))
            threads.append(thread)
            thread.start()
            time.sleep(args.rate_limit)

        print(f"Testing for CSRF on {url}...")
        thread = threading.Thread(target=test_csrf, args=(url, session))
        threads.append(thread)
        thread.start()
        time.sleep(args.rate_limit)

    for thread in threads:
        thread.join()

    print("Scan completed. Generating report...")
    logging.info("Scan completed.")
    generate_report()
    print("Report generated: scan_report.html")

if __name__ == "__main__":
    main()
