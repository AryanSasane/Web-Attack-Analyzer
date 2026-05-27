import argparse
from utils.report import save_json, print_summary

def main():
    parser = argparse.ArgumentParser(description="Web Attack Traffic Analyzer")
    parser.add_argument("--pcap",   help="Path to the .pcap file")
    parser.add_argument("--live",   action="store_true", help="Live capture mode")
    parser.add_argument("--iface",  default=None, help="Network interface for live capture")
    parser.add_argument("--port",   type=int, default=80, help="Port to capture (default to 80)")
    parser.add_argument("--report", help="Save JSON report to this patch")
    parser.add_argument("--dashboard", action="store_true", help="Launch Flask dashboard")
    args = parser.parse_args()

    alerts = []

    if args.pcap:
        from core.pcap_reader import read_pcap
        from core.analyzer import analyze_request
        requests = read_pcap(args.pcap)
        for req in requests:
            alerts.extend(analyze_request(req))
        
    elif args.live:
        from core.capture import start_capture
        alerts = start_capture(interface=args.iface, port=args.port)

    elif args.dashboard:
        from dashboard.app import create_app
        app = create_app()
        print("[+] Dashboard running at http://localhost:5000")
        app.run(debug=True)
        return
    
    else:
        parser.print_help()
        return
    
    print_summary(alerts)
    if args.report:
        save_json(alerts, args.report)
    
if __name__ == "__main__":
    main()