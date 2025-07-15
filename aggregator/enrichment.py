import whois
import requests
import geoip2.database
from aggregator.config import ABUSEIPDB_API_KEY, GEOLITE2_CITY_DB, PASSIVE_DNS_API_KEY

def get_whois_info(ip_address):
    try:
        w = whois.whois(ip_address)
        return w
    except Exception as e:
        print(f"Whois lookup error: {e}")
        return None

def get_abuseipdb_info(ip_address):
    if not ABUSEIPDB_API_KEY:
        print("ABUSEIPDB_API_KEY not set in config.py. Skipping AbuseIPDB lookup.")
        return None

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90&verbose=true"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        return data.get('data')
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB lookup error: {e}")
        return None

def get_geolocation(ip_address):
    try:
        with geoip2.database.Reader(GEOLITE2_CITY_DB) as reader:
            response = reader.city(ip_address)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
    except geoip2.errors.AddressNotFoundError:
        # print(f"Geolocation not found for IP: {ip_address}")
        return None
    except Exception as e:
        print(f"Geolocation lookup error: {e}")
        return None

def get_passive_dns_info(query):
    if not PASSIVE_DNS_API_KEY:
        print("PASSIVE_DNS_API_KEY not set in config.py. Skipping Passive DNS lookup.")
        return None

    # Placeholder for actual Passive DNS API call
    # Example using a hypothetical API:
    # url = f"https://api.passivedns.com/v1/lookup?query={query}"
    # headers = {
    #     'Authorization': f'Bearer {PASSIVE_DNS_API_KEY}'
    # }
    # try:
    #     response = requests.get(url, headers=headers)
    #     response.raise_for_status()
    #     return response.json()
    # except requests.exceptions.RequestException as e:
    #     print(f"Passive DNS lookup error: {e}")
    #     return None
    print(f"Performing Passive DNS lookup for: {query} (API integration pending)")
    return {"message": "Passive DNS lookup not yet implemented with a real API."}

def get_service_name(port):
    # A simple mapping for common ports to service names
    # This can be expanded or replaced with a more comprehensive service lookup
    port_services = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        80: "HTTP",
        110: "POP3",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        3389: "RDP",
        443: "HTTPS",
        445: "SMB/CIFS",
        3306: "MySQL",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Proxy/Alt HTTP"
    }
    return port_services.get(port, "Unknown")