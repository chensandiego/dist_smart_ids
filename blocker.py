import subprocess
import time
import logging
from typing import NoReturn

from config import BLOCKING_DURATION_MINUTES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def block_ip(ip_address: str) -> None:
    logging.info(f"[BLOCKER] Attempting to block IP: {ip_address}")
    try:
        # Add iptables rule to drop traffic from the IP address
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"], check=True)
        logging.info(f"[BLOCKER] Successfully blocked IP: {ip_address} for {BLOCKING_DURATION_MINUTES} minutes.")

        # Schedule unblocking after a certain duration
        # In a real-world scenario, you'd use a more robust scheduling mechanism (e.g., Celery, cron)
        # For this example, we'll just log a message.
        logging.info(f"[BLOCKER] IP {ip_address} will be unblocked in {BLOCKING_DURATION_MINUTES} minutes.")

    except subprocess.CalledProcessError as e:
        logging.error(f"[BLOCKER] Error blocking IP {ip_address}: {e}. Command: {e.cmd}, Return Code: {e.returncode}, Output: {e.output.decode()}")
    except FileNotFoundError:
        logging.error("[BLOCKER] iptables command not found. Make sure iptables is installed and in your PATH.")
    except Exception as e:
        logging.error(f"[BLOCKER] An unexpected error occurred while blocking IP {ip_address}: {e}", exc_info=True)

def unblock_ip(ip_address: str) -> None:
    logging.info(f"[BLOCKER] Attempting to unblock IP: {ip_address}")
    try:
        # Delete iptables rule to allow traffic from the IP address
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"], check=True)
        logging.info(f"[BLOCKER] Successfully unblocked IP: {ip_address}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[BLOCKER] Error unblocking IP {ip_address}: {e}. Command: {e.cmd}, Return Code: {e.returncode}, Output: {e.output.decode()}")
    except FileNotFoundError:
        logging.error("[BLOCKER] iptables command not found. Make sure iptables is installed and in your PATH.")
    except Exception as e:
        logging.error(f"[BLOCKER] An unexpected error occurred while unblocking IP {ip_address}: {e}", exc_info=True)

if __name__ == "__main__":
    # Example usage (for testing)
    test_ip = "192.168.1.100"
    block_ip(test_ip)
    # In a real scenario, you'd have a separate mechanism to call unblock_ip after BLOCKING_DURATION_MINUTES
    # time.sleep(BLOCKING_DURATION_MINUTES * 60)
    # unblock_ip(test_ip)
