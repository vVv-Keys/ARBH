# Bug Bounty Scanner

## The Bug Bounty Scanner is an automated tool designed to assist in the discovery of security vulnerabilities in web applications. It performs a series of tests to identify common vulnerabilities such as SQL injection, cross-site scripting (XSS), command injection, and cross-site request forgery (CSRF). The tool is highly configurable and can be adapted to suit different testing scenarios.

# Features

```
SQL Injection Testing: Checks for SQL injection vulnerabilities by injecting various payloads into input fields.
Cross-site Scripting (XSS) Testing: Identifies XSS vulnerabilities by injecting payloads into input fields and checking for script execution.
Command Injection Testing: Tests for command injection vulnerabilities by injecting payloads into input fields and verifying the response.
CSRF Protection Checks: Detects CSRF vulnerabilities by analyzing forms for missing CSRF tokens.
Headless Browser Support: Utilizes headless browsers for JavaScript rendering and crawling dynamic content.
Multithreading and Rate Limiting: Optimizes performance with multithreading and rate limiting for requests.
Email Alerts: Sends email alerts for critical vulnerabilities found during scanning.
Modular Design: Structured for easy maintenance and further enhancements.
```
# Usage

1. Clone the Repository:

```git clone https://github.com/vVv-Keys/AUTOMATED-RECON-BUG-HUNTING```

2. Install Dependencies:

```pip install -r requirements.txt```

3. Download ChromeDriver and ensure it is in your PATH:

4. Update Configuration:

_ Configure the email settings in bug_bounty_scanner.py for email alerts.
- Update payload files (sql_payloads.txt, xss_payloads.txt, cmd_payloads.txt) with custom payloads if needed.

5. Run the Scanner:
```
python bug_bounty_scanner.py <target_url> [options]
```
# EXAMPLE:

```
python bug_bounty_scanner.py http://example.com/search --login-url http://example.com/login --username admin --password password --proxy http://127.0.0.1:8080 --rate-limit 1 --email alert@example.com --headless
```

# Contributing
Contributions are welcome! If you have any ideas for enhancements, feel free to open an issue or submit a pull request.

# License
This project is licensed under the MIT License - see the LICENSE file for details.
