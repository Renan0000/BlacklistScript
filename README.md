# VirusTotal URL and Domain Scanner

---

## Overview
This Python script is designed to check URLs and domains against VirusTotal's blacklist databases. It automatically submits URLs for scanning if they haven't been previously scanned, processes the results, and sends an email with a summary of the findings.

---

## Prerequisites
- **Python 3.x**: Ensure you have Python 3 installed on your machine.
- **Email Account**: A Gmail account to send the email reports.
- **VirusTotal API Key**: A valid API key from VirusTotal.

---

## Installation

1. **Clone or download the repository:**

   ```bash
   git clone https://github.com/yourusername/virustotal-url-domain-scanner.git
   cd virustotal-url-domain-scanner

2. **Install required Python packages:**

   The script uses `requests` for HTTP requests. Install it using pip:

   ```bash
   pip install requests
   
3. **Configure API Key:**

   Open the script and replace the placeholder with your VirusTotal API key:

   ```python
   headers = {
       "accept": "application/json",
       "x-apikey": "your-virustotal-api-key"
   }
4. **Set up Email Settings:**

   Update the following fields with your Gmail credentials and the recipient's email address:

   ```python
   email_from = "examplesender@gmail.com"  # Your Gmail address
   email_to = "examplereceiver@gmail.com"  # Recipient's email address
5. **Assign Teams to Domains and URLs:**

   Define the teams responsible for specific domains and URLs in the `domains_and_teams` and `urls_and_teams` dictionaries:

   ```python
   domains_and_teams = {
       "domain.com": "team X",
   }

   urls_and_teams = {
       "url.com": "team X",
   }
   
5. **Running the script:**
```bash
python3 virustotal-scanner.py

