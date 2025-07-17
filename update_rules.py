import requests
import os
import tarfile
import shutil
from config import SURICATA_RULES

# URL for the Emerging Threats Open ruleset
ET_OPEN_RULES_URL = "https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules.tar.gz"
TEMP_DIR = "/tmp/suricata_rules"
RULES_DIR = "rules"

def download_and_extract_rules():
    """
    Downloads and extracts the Emerging Threats Open ruleset.
    """
    print("[*] Downloading Suricata rules from Emerging Threats...")
    try:
        response = requests.get(ET_OPEN_RULES_URL, stream=True)
        response.raise_for_status()

        if os.path.exists(TEMP_DIR):
            shutil.rmtree(TEMP_DIR)
        os.makedirs(TEMP_DIR)

        tarball_path = os.path.join(TEMP_DIR, "emerging-all.rules.tar.gz")
        with open(tarball_path, "wb") as f:
            f.write(response.raw.read())

        print("[*] Extracting rules...")
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(path=TEMP_DIR)

        print("[*] Rules extracted successfully.")
        return os.path.join(TEMP_DIR, "rules")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error downloading rules: {e}")
        return None
    except tarfile.TarError as e:
        print(f"[!] Error extracting rules: {e}")
        return None

def update_suricata_rules(extracted_rules_path):
    """
    Updates the local Suricata rules file with the new rules.
    """
    print(f"[*] Updating Suricata rules file: {SURICATA_RULES}")
    try:
        if not os.path.exists(RULES_DIR):
            os.makedirs(RULES_DIR)

        with open(SURICATA_RULES, "w") as main_rules_file:
            for filename in os.listdir(extracted_rules_path):
                if filename.endswith(".rules"):
                    filepath = os.path.join(extracted_rules_path, filename)
                    with open(filepath, "r") as rule_file:
                        main_rules_file.write(f"# Rules from {filename}\n")
                        main_rules_file.write(rule_file.read())
                        main_rules_file.write("\n\n")
        
        print("[*] Suricata rules updated successfully.")
    except IOError as e:
        print(f"[!] Error updating rules file: {e}")

def main():
    """
    Main function to download and update Suricata rules.
    """
    extracted_rules_path = download_and_extract_rules()
    if extracted_rules_path:
        update_suricata_rules(extracted_rules_path)
        # Clean up the temporary directory
        shutil.rmtree(TEMP_DIR)
        print("[*] Cleanup complete.")

if __name__ == "__main__":
    main()