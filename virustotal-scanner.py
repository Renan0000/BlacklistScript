from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import base64
import requests
import time
from datetime import datetime

headers = {
    "accept": "application/json",
    "x-apikey": "" #you virustotal api key
}

#teams X means the team that is responsable for that domain or url

domains_and_teams = {
    "domain.com": "team X",
}

urls_and_teams = {
    "url.com":"team X",

}

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_url(url):
    url_id = encode_url(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        # If URL not found, submit it for scanning
        print(f"URL not found, submitting for scanning: {url}")
        submit_url(url)
        return None
    else:
        print(f"Error verifing the URL {url}: {response.status_code}, Response: {response.text}")
        return None

def submit_url(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    response = requests.post(api_url, headers=headers, data=data)
    if response.status_code == 200:
        print(f"URL submitted successfully: {url}")
        return response.json()
    else:
        print(f"Erro submmiting the URL {url}: {response.status_code}, Response: {response.text}")
        return None

def process_url(url, teams_name):
    json_response_URLscan = check_url(url)

    if (json_response_URLscan and "data" in json_response_URLscan and "attributes" in json_response_URLscan["data"]):
        last_analysis_results = json_response_URLscan["data"]["attributes"]["last_analysis_results"]
        resultados_scan = [
            {"engine_name": details["engine_name"], "result": details["result"]}
            for details in last_analysis_results.values()
            if details["result"] != "clean" and details["result"] != "unrated"
        ]

        engines = [result["engine_name"] for result in resultados_scan] if resultados_scan else []
        message = f"The site {url} was found in the blacklists {', '.join(engines)}." if engines else f"The site {url} was not found in any blacklist."
    else:
        message = f"O site did not return valid results {url}"
        engines = []

    print(message)
    return {"teams": teams_name, "url": url, "engines": engines}

def send_email(results, subject):
    email_from = "examplesender@gmail.com" #Put the email that will send the email
    email_to = "examplereceiver@gmail.com" #Put the email that will receive the table with the results
    email_body = f"""
<html>
<head>
<style>
table {{
    font-family: Arial, sans-serif;
    border-collapse: collapse;
    width: 100%;
}}

th, td {{
    border: 1px solid #dddddd;
    text-align: left;
    padding: 8px;
}}

th {{
    background-color: #f2f2f2;
}}

tr:nth-child(even) {{
    background-color: #f9f9f9;
}}

tr:hover {{
    background-color: #e9e9e9;
}}

.red-row {{
    background-color: #ffcccc;
}}
</style>
</head>
<body>
<p>Here are the results of the scans: </p>
<table>
<tr>
<th>URL</th>
<th>BLACKLIST</th>
<th>TEAM NAME</th>
</tr>
"""
    for result in results:
        url = result["url"]
        team_name = result["team"]
        engines = result["engines"]
        blacklist_str = ', '.join(engines) if engines else "Not in a blacklist"
        row_class = 'class="red-row"' if engines else ''

        email_body += f"""
<tr {row_class}>
<td>{url}</td>
<td>{blacklist_str}</td>
<td>{team_name}</td>
</tr>
"""
    email_body += """
</table>
</body>
</html>
"""

    msg = MIMEMultipart()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = subject
    msg.attach(MIMEText(email_body, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email_from, "")  # put your app password here
        server.sendmail(email_from, email_to, msg.as_string())
        server.close()
        print("Email send succefully")
    except Exception as e:
        print(f"Failed to send the e-mail: {e}")

def process_and_send_email(data, subject_prefix):
    results = []
    batch_size = 4
    for i in range(0, len(data), batch_size):
        batch_items = list(data.items())[i:i + batch_size]
        for url, bu_name in batch_items:
            results.append(process_url(url, bu_name))
        time.sleep(60)  # Sleep for 60 seconds after processing each batch
    current_date = datetime.now().strftime("%d/%m/%Y")
    subject = f"{subject_prefix} - {current_date}"
    send_email(results, subject)

print("Processing URLs")
process_and_send_email(urls_and_teams, "URLs scan results")

print("Processing Domains")
process_and_send_email(domains_and_teams, "Domain scan results")