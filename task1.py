

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def process_packet(packet):
    """Process and display packet information."""
    # Check if packet has IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Initialize protocol name
        proto_name = "Unknown"
        
        # Determine protocol
        if protocol == 6 and TCP in packet:  # TCP
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload) if packet[TCP].payload else b""
        elif protocol == 17 and UDP in packet:  # UDP
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload) if packet[UDP].payload else b""
        elif protocol == 1 and ICMP in packet:  # ICMP
            proto_name = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
            payload = bytes(packet[ICMP].payload) if packet[ICMP].payload else b""
        else:
            src_port = "N/A"
            dst_port = "N/A"
            payload = b""
        
        # Print packet information
        print(f"\n[+] Packet Captured:")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto_name}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Payload (first 50 bytes): {payload[:50].hex() if payload else 'None'}")

def start_sniffer(interface="eth0", count=10):
    """Start packet sniffing on specified interface."""
    try:
        print(f"Starting network sniffer on {interface}...")
        print(f"Capturing {count} packets (Ctrl+C to stop early)...")
        sniff(iface=interface, prn=process_packet, count=count, store=0)
    except PermissionError:
        print("Error: This program requires root privileges. Run with sudo.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Default interface (modify as needed: 'eth0', 'wlan0', etc.)
    interface = "eth0"
    # Number of packets to capture (0 for continuous)
    packet_count = 10
    start_sniffer(interface, packet_count)