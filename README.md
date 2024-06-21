```
██ ▄█▀▓█████▓██   ██▓  ██████ 
██▄█▒ ▓█   ▀ ▒██  ██▒▒██    ▒  
▓███▄░ ▒███    ▒██ ██░░ ▓██▄   
▓██ █▄ ▒▓█  ▄  ░ ▐██▓░  ▒   ██▒
▒██▒ █▄░▒████▒ ░ ██▒▓░▒██████▒▒
▒ ▒▒ ▓▒░░ ▒░ ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░
░ ░▒ ▒░ ░ ░  ░▓██ ░▒░ ░ ░▒  ░ ░
░ ░░ ░    ░   ▒ ▒ ░░  ░  ░  ░  
░  ░      ░  ░░ ░           ░  
              ░ ░ 
```

# Automated Bug Bounty Scanner

```
This project is an automated bug bounty scanner designed to detect common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Command Injection, and Cross-Site Request Forgery (CSRF). It includes features such as headless browsing, email alerts, and a detailed HTML report generation.
```

## Features

```
1. **SQL Injection Detection**
   - Uses a variety of payloads to test for SQL Injection vulnerabilities.
   - Logs potential vulnerabilities and sends email alerts.

2. **Cross-Site Scripting (XSS) Detection**
   - Tests for XSS vulnerabilities using different payloads.
   - Logs potential vulnerabilities and sends email alerts.

3. **Command Injection Detection**
   - Detects possible command injection points.
   - Logs potential vulnerabilities and sends email alerts.

4. **Cross-Site Request Forgery (CSRF) Detection**
   - Checks for missing CSRF tokens in forms.
   - Logs potential vulnerabilities and sends email alerts.

5. **URL Discovery**
   - Discovers URLs and forms on the target site using both requests and headless browsing with Selenium.

6. **Email Alerts**
   - Sends email notifications when vulnerabilities are detected.
   - Configurable via environment variables.

7. **HTML Report Generation**
   - Generates a comprehensive HTML report summarizing the scan results.

8. **Retry Mechanism**
   - Implements retry logic for network requests to handle temporary failures.

9. **Environment Configuration**
   - Uses `.env` file to manage sensitive information such as email credentials and SMTP server details.

10. **Concurrency and Rate Limiting**
    - Utilizes multithreading for concurrent scanning.
    - Supports rate limiting to control the frequency of requests.

11. **Proxy Support**
    - Allows routing requests through a proxy server for additional anonymity or bypassing network restrictions.

12. **Bearer and JWT Authentication**
    - Supports authentication tokens for scanning authenticated endpoints.

13. **User-Agent Randomization**
    - Randomizes User-Agent headers to mimic different browsers and reduce the chance of being blocked.
```

## Requirements

```
- Python 3.6+
- `requests` library
- `beautifulsoup4` library
- `selenium` library
- `retrying` library
- `python-dotenv` library
- Chrome WebDriver (for headless browsing)
```

## Installation

1. Clone the repository:


sh git clone [https://github.com/vVv_Keys/bug-bounty-scanner](https://github.com/vVv-Keys/AUTOMATED-RECON-BUG-HUNTING).git
   cd bug-bounty-scanner


2. Install the required Python packages:

```
pip install -r requirements.txt
```

3. Set up the .env file with your email and SMTP server details:

```
EMAIL_ADDRESS=your_email@example.com
EMAIL_PASSWORD=your_email_password
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
ALERT_EMAIL=alert@example.com
```

4. Download and set up Chrome WebDriver for Selenium:
```
- Follow the instructions at https://sites.google.com/chromium.org/driver/ to download the WebDriver that matches your Chrome version.
- Ensure the WebDriver is in your system's PATH.
```
## USAGE
```
Options:


--login-url : Login URL for authenticated scans.
--username : Username for login.
--password : Password for login.
--proxy : Proxy server to use for requests.
--rate-limit : Rate limit for requests (seconds between requests).
--auth-token : Authentication token for Bearer or JWT based authentication.
--headless : Use headless browser for crawling.
--email : Email address for alerts.
```

## EXAMPLE USAGE:

```
python scanner.py http://example.com --login-url http://example.com/login --username admin --password password --proxy http://127.0.0.1:8080 --rate-limit 0.5 --auth-token YOUR_TOKEN --headless --email alert@example.com
```

## CONTRIBUTING

```
Contributing
Fork the repository.
Create a new branch (git checkout -b feature-branch).
Make your changes and commit them (git commit -am 'Add new feature').
Push to the branch (git push origin feature-branch).
Create a new Pull Request.
```

## LICENSE
```
This project is licensed under the MIT License. See the LICENSE file for details.
```
