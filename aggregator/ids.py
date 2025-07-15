import argparse
import subprocess
from dashboard import start_web
from pcap_monitor import monitor_directory

def main():
    parser = argparse.ArgumentParser(description="智能混合型網路入侵偵測系統")
    parser.add_argument("--mode", choices=["live", "pcap", "monitor"], required=True, help="執行模式")
    parser.add_argument("--file", help="PCAP 檔案路徑（僅限 pcap 模式）")
    parser.add_argument("--web", action="store_true", help="啟動 Web 儀表板")

    args = parser.parse_args()

    if args.web:
        start_web()

    if args.mode == "live":
        print("🚨 Starting Suricata EVE JSON parser...")
        # Start the Suricata EVE JSON parser as a subprocess
        subprocess.Popen(["python", "suricata_alert_parser.py"])
    elif args.mode == "pcap":
        if not args.file:
            print("❗ 請指定 --file 路徑")
        else:
            # This part needs to be re-evaluated if pcap analysis is still needed
            # For now, it's left as a placeholder.
            print(f"📦 PCAP analysis for {args.file} is not yet integrated with Suricata EVE JSON.")
    elif args.mode == "monitor":
        monitor_directory()

if __name__ == "__main__":
    main()