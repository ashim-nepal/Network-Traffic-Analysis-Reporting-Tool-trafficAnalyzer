import subprocess
from datetime import datetime

PCAP_FILE = "captures/traffic.pcap"
REPORT_FILE = "reports/analysis_report.txt"

def run_tshark(filter_expr=None):
    command = ["tshark", "-r", PCAP_FILE]
    if filter_expr:
        command.extend(["-Y", filter_expr])
    try:
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return output.decode().strip()
    except subprocess.CalledProcessError:
        return ""

def count_packets(filter_expr=None):
    output = run_tshark(filter_expr)
    if not output:
        return 0
    return len(output.splitlines())

def main():
    report = []

    report.append("Wireshark Traffic Analysis Report")
    report.append(f"Date: {datetime.now()}")
    report.append("=" * 50)

    total_packets = count_packets()
    dns_packets = count_packets("dns")
    http_packets = count_packets("http")
    icmp_packets = count_packets("icmp")

    report.append(f"\nTotal Packets Captured: {total_packets}")
    report.append(f"DNS Packets: {dns_packets}")
    report.append(f"HTTP Packets: {http_packets}")
    report.append(f"ICMP Packets: {icmp_packets}")

    # Suspicious indicator
    report.append("\nObservations:")
    if dns_packets > 0:
        report.append("- DNS activity detected (normal for browsing)")
    if http_packets > 0:
        report.append("- Unencrypted HTTP traffic detected")
    if icmp_packets > 5:
        report.append("- High ICMP activity (possible scanning or troubleshooting)")

    if total_packets == 0:
        report.append("- No traffic captured (check interface or capture file)")

    # Save
    with open(REPORT_FILE, "w") as f:
        for line in report:
            f.write(line + "\n")

    print("\nTraffic analysis completed.")
    print(f"Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    main()
