import whois
import requests
import geoip2.database
import os
from config import ABUSEIPDB_API_KEY, GEOLITE2_CITY_DB, PASSIVE_DNS_API_KEY

def get_whois_info(ip_address):
    print(f"[Enrichment] Performing WHOIS lookup for: {ip_address}")
    try:
        w = whois.whois(ip_address)
        print(f"[Enrichment] WHOIS result: {w}")
        return w
    except Exception as e:
        print(f"[Enrichment ERROR] Whois lookup error for {ip_address}: {e}")
        return None

def get_abuseipdb_info(ip_address):
    print(f"[Enrichment] Performing AbuseIPDB lookup for: {ip_address}")
    if not ABUSEIPDB_API_KEY:
        print("[Enrichment] ABUSEIPDB_API_KEY not set. Skipping AbuseIPDB lookup.")
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
        print(f"[Enrichment] AbuseIPDB result for {ip_address}: {data.get('data')}")
        return data.get('data')
    except requests.exceptions.RequestException as e:
        print(f"[Enrichment ERROR] AbuseIPDB lookup error for {ip_address}: {e}")
        return None

# Use an absolute path for the GeoLite2 database within the Docker container
ABSOLUTE_GEOLITE2_CITY_DB = "/app/GeoLite2-City.mmdb"

def get_geolocation(ip_address):
    print(f"[Enrichment] Performing geolocation lookup for: {ip_address}")
    if not os.path.exists(ABSOLUTE_GEOLITE2_CITY_DB):
        print(f"[Enrichment ERROR] GeoLite2 database not found at {ABSOLUTE_GEOLITE2_CITY_DB}. Skipping geolocation.")
        return None
    try:
        with geoip2.database.Reader(ABSOLUTE_GEOLITE2_CITY_DB) as reader:
            response = reader.city(ip_address)
            geo_info = {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
            print(f"[Enrichment] Geolocation result for {ip_address}: {geo_info}")
            return geo_info
    except geoip2.errors.AddressNotFoundError:
        print(f"[Enrichment] Geolocation not found for IP: {ip_address}")
        return None
    except Exception as e:
        print(f"[Enrichment ERROR] Geolocation lookup error for {ip_address}: {e}")
        return None

def get_passive_dns_info(query):
    print(f"[Enrichment] Performing Passive DNS lookup for: {query}")
    if not PASSIVE_DNS_API_KEY:
        print("[Enrichment] PASSIVE_DNS_API_KEY not set. Skipping Passive DNS lookup.")
        return None

    # Placeholder for actual Passive DNS API call
    print(f"[Enrichment] Performing Passive DNS lookup for: {query} (API integration pending)")
    return {"message": "Passive DNS lookup not yet implemented with a real API."}

def get_service_name(port):
    print(f"[Enrichment] Getting service name for port: {port}")
    port_services = {
        20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 80: "HTTP", 110: "POP3",
        137: "NetBIOS Name Service", 138: "NetBIOS Datagram Service", 139: "NetBIOS Session Service",
        143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 3389: "RDP", 443: "HTTPS",
        445: "SMB/CIFS", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Proxy/Alt HTTP"
    }
    service = port_services.get(port, "Unknown")
    print(f"[Enrichment] Service for port {port}: {service}")
    return service
