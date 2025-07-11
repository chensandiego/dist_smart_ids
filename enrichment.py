
import whois

def get_whois_info(ip_address):
    try:
        w = whois.whois(ip_address)
        return w
    except Exception as e:
        print(f"Whois lookup error: {e}")
        return None
