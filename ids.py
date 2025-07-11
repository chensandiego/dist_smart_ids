import argparse
from scapy.all import sniff, rdpcap
from detector import packet_handler
from database import init_db
from pcap_monitor import monitor_directory

def live_mode(interface=None):
    print("🚨 啟動即時監控模式...")
    sniff(prn=packet_handler, store=False, iface=interface)

def pcap_mode(file_path):
    print(f"📦 載入 PCAP 分析: {file_path}")
    packets = rdpcap(file_path)
    for pkt in packets:
        packet_handler(pkt)

if __name__ == "__main__":
    from dashboard import start_web  # 匯入 Web Dashboard

    parser = argparse.ArgumentParser(description="智能混合型網路入侵偵測系統")
    parser.add_argument("--mode", choices=["live", "pcap", "monitor"], required=True, help="執行模式")
    parser.add_argument("--file", help="PCAP 檔案路徑（僅限 pcap 模式）")
    parser.add_argument("--interface", help="指定監控的網卡")
    parser.add_argument("--web", action="store_true", help="啟動 Web 儀表板")

    args = parser.parse_args()

    if args.web:
        start_web()

    if args.mode == "live":
        live_mode(interface=args.interface)
    elif args.mode == "pcap":
        if not args.file:
            print("❗ 請指定 --file 路徑")
        else:
            pcap_mode(args.file)
    elif args.mode == "monitor":
        monitor_directory()
