
import os
import re
from exchangelib import Credentials, Account, Configuration, DELEGATE
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
import urllib3
import logging

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
# In a real application, use a secure method to store and access credentials
EXCHANGE_USERNAME = os.environ.get("EXCHANGE_USERNAME", "your_email@example.com")
EXCHANGE_PASSWORD = os.environ.get("EXCHANGE_PASSWORD", "your_password")
EXCHANGE_SERVER = os.environ.get("EXCHANGE_SERVER", "your_exchange_server")

# --- Email Analysis ---

def analyze_email_headers(email):
    """Analyzes email headers for common signs of phishing or spoofing."""
    suspicious_indicators = []
    
    # Example: Check if 'Reply-To' is different from 'From'
    if email.reply_to and email.reply_to.email_address != email.sender.email_address:
        suspicious_indicators.append("Mismatch between 'From' and 'Reply-To' headers.")
        
    # Add more header checks here (e.g., SPF/DKIM/DMARC analysis if possible)
    
    return suspicious_indicators

def analyze_email_body(email):
    """Scans the email body for suspicious patterns."""
    suspicious_indicators = []
    
    # Regex for common phishing phrases (simplified)
    phishing_phrases = [
        r"verify your account",
        r"update your payment details",
        r"urgent action required",
        r"your account has been suspended"
    ]
    
    for phrase in phishing_phrases:
        if re.search(phrase, email.body, re.IGNORECASE):
            suspicious_indicators.append(f"Detected suspicious phrase: '{phrase}'")
            
    # Regex for suspicious links
    suspicious_links = re.findall(r'href=['"](http[s]?://[^'"]+)['"]', email.body)
    if suspicious_links:
        suspicious_indicators.append(f"Found links in email: {', '.join(suspicious_links)}")
        
    return suspicious_indicators

def analyze_attachments(email):
    """Checks for potentially dangerous attachments."""
    suspicious_indicators = []
    
    dangerous_extensions = [".exe", ".zip", ".scr", ".bat", ".pif", ".com"]
    
    if email.attachments:
        for attachment in email.attachments:
            for ext in dangerous_extensions:
                if attachment.name.lower().endswith(ext):
                    suspicious_indicators.append(f"Dangerous attachment type detected: {attachment.name}")
                    
    return suspicious_indicators

# --- Main Scanner ---

def scan_exchange_inbox():
    """Connects to Exchange, fetches unread emails, and analyzes them."""
    try:
        # This is for development/testing and disables SSL verification.
        # In production, you should configure proper SSL certificate validation.
        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
        
        creds = Credentials(username=EXCHANGE_USERNAME, password=EXCHANGE_PASSWORD)
        
        config = Configuration(server=EXCHANGE_SERVER, credentials=creds)
        
        account = Account(primary_smtp_address=EXCHANGE_USERNAME, config=config,
                          autodiscover=False, access_type=DELEGATE)
        
        logging.info(f"Successfully connected to {EXCHANGE_SERVER} for account {EXCHANGE_USERNAME}")
        
        # Fetch unread emails from the Inbox
        for email in account.inbox.filter(is_read=False):
            logging.info(f"Scanning email: '{email.subject}' from {email.sender.email_address}")
            
            all_suspicious_indicators = []
            all_suspicious_indicators.extend(analyze_email_headers(email))
            all_suspicious_indicators.extend(analyze_email_body(email))
            all_suspicious_indicators.extend(analyze_attachments(email))
            
            if all_suspicious_indicators:
                # Here, you would integrate with your IDS
                # For now, we'll just log the findings
                logging.warning(f"Suspicious email found: '{email.subject}'")
                for indicator in all_suspicious_indicators:
                    logging.warning(f"  - {indicator}")
            else:
                logging.info(f"Email '{email.subject}' appears to be clean.")
                
            # Mark the email as read so it's not scanned again
            email.is_read = True
            email.save()

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    logging.info("Starting email scanner...")
    # In a real deployment, this would run as a continuous service
    scan_exchange_inbox()
    logging.info("Email scanner finished.")
