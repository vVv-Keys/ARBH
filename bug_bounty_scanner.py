import requests
import threading
import argparse
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from retrying import retry
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

# Function to send email alerts
def send_email_alert(subject, body, to_email):
    from_email = os.getenv('EMAIL_ADDRESS')
    from_password = os.getenv('EMAIL_PASSWORD')
    
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT')))
        server.starttls()
        server.login(from_email, from_password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        logging.info("Email alert sent successfully")
    except Exception as e:
        logging.error(f"Error sending email alert: {e}")

@retry(stop_max_attempt_number=3, wait_fixed=2000)
def request_with_retry(session, url, params):
    return session.get(url, params=params, timeout=10)

# Function to test for SQL Injection
def test_sql_injection(url, payload, session):
    try:
        response = request_with_retry(session, url, params={'q': payload})
        if "sql syntax" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
            logging.info(f"Possible SQL Injection vulnerability found with payload: {payload}")
            print(f"Possible SQL Injection vulnerability found with payload: {payload}")
            send_email_alert("SQL Injection Found", f"Possible SQL Injection vulnerability found with payload: {payload}", os.getenv('ALERT_EMAIL'))
        else:
            logging.info(f"No SQL Injection vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing SQL Injection with payload {payload}: {e}")

# Function to test for XSS
def test_xss(url, payload, session):
    try:
        response = request_with_retry(session, url, params={'q': payload})
        if payload in response.text:
            logging.info(f"Possible XSS vulnerability found with payload: {payload}")
            print(f"Possible XSS vulnerability found with payload: {payload}")
            send_email_alert("XSS Found", f"Possible XSS vulnerability found with payload: {payload}", os.getenv('ALERT_EMAIL'))
        else:
            logging.info(f"No XSS vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing XSS with payload {payload}: {e}")

# Function to test for Command Injection
def test_cmd_injection(url, payload, session):
    try:
        response = request_with_retry(session, url, params={'q': payload})
        if "command not found" in response.text.lower() or "not recognized as an internal or external command" in response.text.lower():
            logging.info(f"Possible Command Injection vulnerability found with payload: {payload}")
            print(f"Possible Command Injection vulnerability found with payload: {payload}")
            send_email_alert("Command Injection Found", f"Possible Command Injection vulnerability found with payload: {payload}", os.getenv('ALERT_EMAIL'))
        else:
            logging.info(f"No Command Injection vulnerability found with payload: {payload}")
    except requests.RequestException as e:
        logging.error(f"Error testing Command Injection with payload {payload}: {e}")

# Function to test for CSRF protection
def test_csrf(url, session):
    try:
        response = request_with_retry(session, url, params={})
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                logging.info(f"Possible CSRF vulnerability found in form at {url}")
                print(f"Possible CSRF vulnerability found in form at {url}")
                send_email_alert("CSRF Found", f"Possible CSRF vulnerability found in form at {url}", os.getenv('ALERT_EMAIL'))
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
    parser.add_argument('--auth-token', type=str, help='Authentication token for Bearer or JWT based authentication')
    parser.add_argument('--headless', action='store_true', help='Use headless browser for crawling')
    parser.add_argument('--email', type=str, help='Email address for alerts')
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

# Function to discover URLs using a headless browser
def discover_urls_headless(base_url):
    options = Options()
    options.headless = True
    browser = webdriver.Chrome(options=options)
    browser.get(base_url)
    urls = set()
    soup = BeautifulSoup(browser.page_source, 'html.parser')
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
    browser.quit()
    return urls

# Function to discover URLs without a headless browser
def discover_urls(base_url, session):
    urls = set()
    try:
        response = request_with_retry(session, base_url, params={})
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
    if args.auth_token:
        session.headers.update({'Authorization': f'Bearer {args.auth_token}'})
    if args.login_url and args.username and args.password:
        session = login(args.login_url, args.username, args.password, args.proxy)

    if args.headless:
        urls = discover_urls_headless(target_url)
    else:
        urls = discover_urls(target_url, session)
    urls.add(target_url)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for url in urls:
            print(f"Testing for SQL Injection on {url}...")
            for payload in sql_injection_payloads:
                futures.append(executor.submit(test_sql_injection, url, payload, session))
                time.sleep(args.rate_limit)

            print(f"Testing for XSS on {url}...")
            for payload in xss_payloads:
                futures.append(executor.submit(test_xss, url, payload, session))
                time.sleep(args.rate_limit)

            print(f"Testing for Command Injection on {url}...")
            for payload in cmd_injection_payloads:
                futures.append(executor.submit(test_cmd_injection, url, payload, session))
                time.sleep(args.rate_limit)

            print(f"Testing for CSRF on {url}...")
            futures.append(executor.submit(test_csrf, url, session))
            time.sleep(args.rate_limit)

        for future in futures:
            future.result()

    print("Scan completed. Generating report...")
    logging.info("Scan completed.")
    generate_report()
    print("Report generated: scan_report.html")

if __name__ == "__main__":
    main()
