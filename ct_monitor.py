import requests
import subprocess
import yaml
import time
import csv
import warnings
from datetime import datetime, UTC
from typing import List, Tuple
from pathlib import Path
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

print(r"""\
        __  _____    ____  ___________
   / / / /   |  / __ \/ ____/ ___/
  / /_/ / /| | / / / / __/  \__ \ 
 / __  / ___ |/ /_/ / /___ ___/ / 
/_/ /_/_/  |_/_____/_____//____/  
                                  
From the Depths, We See All.
""")

warnings.simplefilter("ignore", InsecureRequestWarning)
print ('Warnings have been silenced')

CONFIG_PATH = "config.yaml"
DATA_DIR = "monitor_data"
SOURCE_TAG = "ct-log"  # Tag domains discovered from Certificate Transparency logs

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

def fetch_ct_domains(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&exclude=expired&output=json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            # Normalize domains to lowercase and strip whitespace
            def normalize(entry: str) -> str:
                return entry.lstrip("*.").strip().lower()
            # Normalize each name_value entry and handle duplicates
            return list({
                normalize(name)
                for entry in data
                for name in entry.get("name_value", "").split("\n")
            })
#            return list({entry["name_value"].strip().lower() for entry in data})
        else:
            print(f"[!] Failed to fetch data for {domain}: {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching CT data for {domain}: {e}")
    return []

def scan_ports(domain: str, risky_ports: set) -> Tuple[bool, List[int], List[int]]:
    try:
        # Use nmap -F (top 100 ports)
        result = subprocess.run(
            ["nmap", "-F", domain],
            capture_output=True,
            text=True,
            timeout=60
        )
        open_ports = []
        risky_found = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = int(line.split("/")[0])
                open_ports.append(port)
                if port in risky_ports:
                    risky_found.append(port)
        return bool(open_ports), open_ports, risky_found
    except subprocess.TimeoutExpired:
        print(f"[!] Nmap scan timed out for {domain}")
        return False, [], []
    except Exception as e:
        print(f"[!] Error scanning {domain}: {e}")
        return False, [], []

def detect_login_page(domain: str, port: int) -> bool:
    try:
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{domain}:{port}"
        response = requests.get(url, timeout=10, verify=False)
        page = response.text.lower()
        indicators = ["login", "sign in", "username", "password", 'type="password"']
        return any(keyword in page for keyword in indicators)
    except Exception as e:
        print(f"[!] Error detecting login page on {domain}:{port} - {e}")
        return False



def send_slack_alert(webhook_url: str, domain: str, ports: List[int]):
    try:
        message = {
            "text": f":warning: *Risky ports found on new domain!* `{domain}`\nOpen risky ports: `{ports}`"
        }
        requests.post(webhook_url, json=message, timeout=10)
    except Exception as e:
        print(f"[!] Failed to send Slack alert: {e}")

def send_login_page_alert(webhook_url: str, domain: str, port: int):
    message = f":lock: *Login page detected* on `{domain}:{port}`"
    try:
        requests.post(webhook_url, json={"text": message})
    except Exception as e:
        print(f"[!] Failed to send Slack login alert for {domain}:{port} - {e}")

def load_list(path: Path) -> List[str]:
    if path.exists():
        return path.read_text().splitlines()
    return []

def save_list(path: Path, items: List[str]):
    # Write sorted unique items
    path.write_text("\n".join(sorted(set(items))))

def log_to_csv(log_path: Path, domain: str, open_ports: List[int], risky_ports: List[int], source: str):
    file_exists = log_path.exists()
    with log_path.open('a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["timestamp", "domain", "open_ports", "risky_ports", "source"])
        writer.writerow([
            datetime.now(UTC).isoformat(),
            domain,
            ",".join(map(str, open_ports)) if open_ports else "None",
            ",".join(map(str, risky_ports)) if risky_ports else "None",
            source
        ])
        csvfile.flush()

def monitor():
    config = load_config()
    risky_ports = set(config.get("risky_ports", []))
    domains = config.get("domains", [])
    slack_webhook = config.get("slack", {}).get("webhook_url", "")

    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

    for root_domain in domains:
        print(f"\n[*] Monitoring CT logs for: {root_domain}")

        subdomains = fetch_ct_domains(root_domain)
        # Tag subdomains with source
        subdomains = [f"{sub}|source={SOURCE_TAG}" for sub in subdomains]

        new_domains_path = Path(DATA_DIR) / f"{root_domain}_new_domains.txt"
        known_domains_path = Path(DATA_DIR) / f"{root_domain}_known_domains.txt"
        log_path = Path(DATA_DIR) / f"{root_domain}_scan_log.csv"

        known = set(load_list(known_domains_path))
        new = set(load_list(new_domains_path))

        # Only scan domains that are not already in the known or new lists.
        to_scan = [d for d in subdomains if d not in known and d not in new]

        print(f"[+] Found {len(to_scan)} new domains to scan for {root_domain}")

        for tagged_domain in to_scan:
            # Split the domain and source tag
            try:
                domain, tag = tagged_domain.split("|source=")
            except ValueError:
                domain = tagged_domain
                tag = SOURCE_TAG

            print(f"[*] Scanning {domain} (source: {tag})...")
            is_live, open_ports, risky_found = scan_ports(domain, risky_ports)
            print(f"[DEBUG] Domain: {domain}, Open Ports: {open_ports}, Risky Ports: {risky_found}")

            # 1. Send alert if risky ports found
            if is_live:
                known.add(tagged_domain)
                print(f"[+] {domain} is live with open ports: {open_ports}")
                if risky_found and slack_webhook:
                    send_slack_alert(slack_webhook, domain, risky_found)

                # 2. Detect login pages on HTTP-related ports
                http_ports = [80, 443, 8080, 8000, 8443]
                for port in open_ports:
                    if port in http_ports:
                        if detect_login_page(domain, port):
                            print(f"[!] Login page detected on {domain}:{port}")
                            if slack_webhook:
                                send_login_page_alert(slack_webhook, domain, port)
            else:
                new.add(tagged_domain)
                print(f"[-] No open ports found on {domain}, storing for recheck.")

            print(f"[DEBUG] Logging to CSV - Domain: {domain}, Open Ports: {open_ports}, Risky: {risky_found}")
            log_to_csv(log_path, domain, open_ports, risky_found, tag)
            time.sleep(3)  # Delay between scans

        save_list(known_domains_path, list(known))
        save_list(new_domains_path, list(new))

    print("\n[✓] Monitoring complete.")

if __name__ == "__main__":
    monitor()

import requests
import subprocess
import yaml
import time
import csv
import warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, UTC
from typing import List, Tuple
from pathlib import Path
from bs4 import BeautifulSoup


warnings.simplefilter("ignore", InsecureRequestWarning)
print ('Warnings have been silenced')

CONFIG_PATH = "config.yaml"
DATA_DIR = "monitor_data"
SOURCE_TAG = "ct-log"  # Tag domains discovered from Certificate Transparency logs

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

def fetch_ct_domains(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&exclude=expired&output=json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            # Normalize domains to lowercase and strip whitespace
            def normalize(entry: str) -> str:
                return entry.lstrip("*.").strip().lower()
            # Normalize each name_value entry and handle duplicates
            return list({
                normalize(name)
                for entry in data
                for name in entry.get("name_value", "").split("\n")
            })
#            return list({entry["name_value"].strip().lower() for entry in data})
        else:
            print(f"[!] Failed to fetch data for {domain}: {response.status_code}")
    except Exception as e:
        print(f"[!] Error fetching CT data for {domain}: {e}")
    return []

def scan_ports(domain: str, risky_ports: set) -> Tuple[bool, List[int], List[int]]:
    try:
        # Use nmap -F (top 100 ports)
        result = subprocess.run(
            ["nmap", "-F", domain],
            capture_output=True,
            text=True,
            timeout=60
        )
        open_ports = []
        risky_found = []
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = int(line.split("/")[0])
                open_ports.append(port)
                if port in risky_ports:
                    risky_found.append(port)
        return bool(open_ports), open_ports, risky_found
    except subprocess.TimeoutExpired:
        print(f"[!] Nmap scan timed out for {domain}")
        return False, [], []
    except Exception as e:
        print(f"[!] Error scanning {domain}: {e}")
        return False, [], []

def detect_login_page(domain: str, port: int) -> bool:
    try:
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{domain}:{port}"
        response = requests.get(url, timeout=10, verify=False)
        page = response.text.lower()
        indicators = ["login", "sign in", "username", "password", 'type="password"']
        return any(keyword in page for keyword in indicators)
    except Exception as e:
        print(f"[!] Error detecting login page on {domain}:{port} - {e}")
        return False



def send_slack_alert(webhook_url: str, domain: str, ports: List[int]):
    try:
        message = {
            "text": f":warning: *Risky ports found on new domain!* `{domain}`\nOpen risky ports: `{ports}`"
        }
        requests.post(webhook_url, json=message, timeout=10)
    except Exception as e:
        print(f"[!] Failed to send Slack alert: {e}")

def send_login_page_alert(webhook_url: str, domain: str, port: int):
    message = f":lock: *Login page detected* on `{domain}:{port}`"
    try:
        requests.post(webhook_url, json={"text": message})
    except Exception as e:
        print(f"[!] Failed to send Slack login alert for {domain}:{port} - {e}")

def load_list(path: Path) -> List[str]:
    if path.exists():
        return path.read_text().splitlines()
    return []

def save_list(path: Path, items: List[str]):
    # Write sorted unique items
    path.write_text("\n".join(sorted(set(items))))

def log_to_csv(log_path: Path, domain: str, open_ports: List[int], risky_ports: List[int], source: str):
    file_exists = log_path.exists()
    with log_path.open('a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["timestamp", "domain", "open_ports", "risky_ports", "source"])
        writer.writerow([
            datetime.now(UTC).isoformat(),
            domain,
            ",".join(map(str, open_ports)) if open_ports else "None",
            ",".join(map(str, risky_ports)) if risky_ports else "None",
            source
        ])
        csvfile.flush()

def monitor():
    config = load_config()
    risky_ports = set(config.get("risky_ports", []))
    domains = config.get("domains", [])
    slack_webhook = config.get("slack", {}).get("webhook_url", "")

    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

    for root_domain in domains:
        print(f"\n[*] Monitoring CT logs for: {root_domain}")

        subdomains = fetch_ct_domains(root_domain)
        # Tag subdomains with source
        subdomains = [f"{sub}|source={SOURCE_TAG}" for sub in subdomains]

        new_domains_path = Path(DATA_DIR) / f"{root_domain}_new_domains.txt"
        known_domains_path = Path(DATA_DIR) / f"{root_domain}_known_domains.txt"
        log_path = Path(DATA_DIR) / f"{root_domain}_scan_log.csv"

        known = set(load_list(known_domains_path))
        new = set(load_list(new_domains_path))

        # Only scan domains that are not already in the known or new lists.
        to_scan = [d for d in subdomains if d not in known and d not in new]

        print(f"[+] Found {len(to_scan)} new domains to scan for {root_domain}")

        for tagged_domain in to_scan:
            # Split the domain and source tag
            try:
                domain, tag = tagged_domain.split("|source=")
            except ValueError:
                domain = tagged_domain
                tag = SOURCE_TAG

            print(f"[*] Scanning {domain} (source: {tag})...")
            is_live, open_ports, risky_found = scan_ports(domain, risky_ports)
            print(f"[DEBUG] Domain: {domain}, Open Ports: {open_ports}, Risky Ports: {risky_found}")

            # 1. Send alert if risky ports found
            if is_live:
                known.add(tagged_domain)
                print(f"[+] {domain} is live with open ports: {open_ports}")
                if risky_found and slack_webhook:
                    send_slack_alert(slack_webhook, domain, risky_found)

                # 2. Detect login pages on HTTP-related ports
                http_ports = [80, 443, 8080, 8000, 8443]
                for port in open_ports:
                    if port in http_ports:
                        if detect_login_page(domain, port):
                            print(f"[!] Login page detected on {domain}:{port}")
                            if slack_webhook:
                                send_login_page_alert(slack_webhook, domain, port)
            else:
                new.add(tagged_domain)
                print(f"[-] No open ports found on {domain}, storing for recheck.")

            print(f"[DEBUG] Logging to CSV - Domain: {domain}, Open Ports: {open_ports}, Risky: {risky_found}")
            log_to_csv(log_path, domain, open_ports, risky_found, tag)
            time.sleep(3)  # Delay between scans

        save_list(known_domains_path, list(known))
        save_list(new_domains_path, list(new))

    print("\n[✓] Monitoring complete.")

if __name__ == "__main__":
    monitor()
