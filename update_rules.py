import requests
import os
import time

# URL for Emerging Threats Open ruleset
ET_OPEN_RULES_URL = "https://rules.emergingthreats.net/open/suricata/emerging.rules"
RULES_FILE_PATH = "rules/suricata.rules"

def download_rules(url, destination):
    print(f"[*] Downloading rules from: {url}")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise an exception for HTTP errors
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[+] Rules downloaded successfully to: {destination}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[-] Error downloading rules: {e}")
        return False

def restart_suricata_service():
    # In a Docker Compose environment, this would typically involve restarting the Suricata service.
    # For now, we'll just print a message. In a real deployment, you'd use `docker-compose restart suricata`
    # or send a signal to the Suricata process to reload rules.
    print("[!] Please restart the Suricata service to load new rules.")

def main():
    print("[*] Starting automated Suricata rule update...")
    if download_rules(ET_OPEN_RULES_URL, RULES_FILE_PATH):
        restart_suricata_service()
    print("[*] Rule update process finished.")

if __name__ == "__main__":
    main()
