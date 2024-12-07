from scapy.all import *

# This function will be called for every captured packet
def packet_callback(packet):
    print("-" * 80)
    print("Capturing Packet...\n")

    # =======================
    # Link Layer (Ethernet)
    # =======================
    if packet.haslayer(Ether):
        eth_src = packet[Ether].src  # Source MAC address
        eth_dst = packet[Ether].dst  # Destination MAC address
        print(f"Link Layer (Ethernet):")
        print(f"  - Source MAC: {eth_src}")
        print(f"  - Destination MAC: {eth_dst}")

    # ===========================
    # Internet Layer (IP, ICMP)
    # ===========================
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        ip_proto = packet[IP].proto  # Protocol (TCP, UDP, ICMP, etc.)
        print(f"\nInternet Layer (IP):")
        print(f"  - Source IP: {ip_src}")
        print(f"  - Destination IP: {ip_dst}")
        print(f"  - Protocol: {get_protocol_name(ip_proto)}")

        # ICMP specific details (for Ping requests, etc.)
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type  # Type of ICMP message (Echo Request, Echo Reply, etc.)
            icmp_code = packet[ICMP].code  # Code of ICMP message
            print(f"  - ICMP Type: {icmp_type}, Code: {icmp_code}")
        
        # IPv6 support (if captured)
        elif packet.haslayer(IPv6):
            ipv6_src = packet[IPv6].src
            ipv6_dst = packet[IPv6].dst
            print(f"  - IPv6 Source: {ipv6_src}, IPv6 Destination: {ipv6_dst}")

    # ==========================
    # Transport Layer (TCP, UDP)
    # ==========================
    if packet.haslayer(TCP):
        tcp_sport = packet[TCP].sport  # Source Port
        tcp_dport = packet[TCP].dport  # Destination Port
        print(f"\nTransport Layer (TCP):")
        print(f"  - Source Port: {tcp_sport}")
        print(f"  - Destination Port: {tcp_dport}")
        print(f"  - Sequence Number: {packet[TCP].seq}")
        print(f"  - Acknowledgement Number: {packet[TCP].ack}")
        print(f"  - TCP Flags: {packet[TCP].flags}")

        # Additional details like TCP Options, Window Size
        print(f"  - Window Size: {packet[TCP].window}")
        if packet.haslayer(Raw):
            print(f"  - Raw Payload: {packet[Raw].load[:50]}...")  # Show a part of the application data if available

    elif packet.haslayer(UDP):
        udp_sport = packet[UDP].sport  # Source Port
        udp_dport = packet[UDP].dport  # Destination Port
        print(f"\nTransport Layer (UDP):")
        print(f"  - Source Port: {udp_sport}")
        print(f"  - Destination Port: {udp_dport}")

    # ==========================
    # Application Layer (HTTP, DNS, etc.)
    # ==========================
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')  # Try to decode raw payload
            if "HTTP" in raw_data:
                print(f"\nApplication Layer (HTTP):")
                print(f"  - HTTP Data (Partial): {raw_data[:100]}...")
            elif "DNS" in raw_data:
                print(f"\nApplication Layer (DNS):")
                print(f"  - DNS Query: {raw_data[:100]}...")
        except:
            print("\nApplication Layer: Raw Data (Unable to decode)")

    print("-" * 80)

# Helper function to map protocol numbers to their names
def get_protocol_name(proto_num):
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
    }
    return protocol_map.get(proto_num, 'Unknown')

# Start sniffing the network; the prn argument specifies the callback function to call for each packet
print("Starting the sniffer...")
sniff(prn=packet_callback, store=0, count=0)  # count=0 means capture indefinitely until manually stopped