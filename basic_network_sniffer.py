from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from datetime import datetime


# Protocol numbers
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}


# Convert TCP flag letters to full names
def get_tcp_flags(flags):
    flag_names = {
        "S": "SYN",
        "A": "ACK",
        "P": "PSH",
        "F": "FIN",
        "R": "RST",
    }

    names = []

    for flag in str(flags):
        if flag in flag_names:
            names.append(flag_names[flag])

    if names:
        return " + ".join(names)

    return "None"


def process_packet(packet):
    print("=" * 70)

    # Display current time
    print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Check for ARP packets
    if packet.haslayer(ARP):
        arp = packet[ARP]

        print("Protocol        :", "ARP")
        print("Source MAC      :", arp.hwsrc)
        print("Destination MAC :", arp.hwdst)
        print("Source IP       :", arp.psrc)
        print("Destination IP  :", arp.pdst)

    # Check for IPv4 packets
    elif packet.haslayer(IP):
        ip = packet[IP]

        print("Source IP       :", ip.src)
        print("Destination IP  :", ip.dst)

        protocol_name = PROTOCOLS.get(
            ip.proto,
            f"Unknown ({ip.proto})"
        )

        print("Protocol        :", protocol_name)

        # TCP information
        if packet.haslayer(TCP):
            tcp = packet[TCP]

            print("Source Port     :", tcp.sport)
            print("Destination Port:", tcp.dport)
            print("TCP Flags       :", get_tcp_flags(tcp.flags))

        # UDP information
        elif packet.haslayer(UDP):
            udp = packet[UDP]

            print("Source Port     :", udp.sport)
            print("Destination Port:", udp.dport)

        # ICMP information
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]

            print("ICMP Type       :", icmp.type)
            print("ICMP Code       :", icmp.code)

    # Check for IPv6 packets
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]

        print("Source IPv6     :", ipv6.src)
        print("Destination IPv6:", ipv6.dst)

        protocol_name = PROTOCOLS.get(
            ipv6.nh,
            f"Unknown ({ipv6.nh})"
        )

        print("Next Header     :", protocol_name)

        # TCP information
        if packet.haslayer(TCP):
            tcp = packet[TCP]

            print("Source Port     :", tcp.sport)
            print("Destination Port:", tcp.dport)
            print("TCP Flags       :", get_tcp_flags(tcp.flags))

        # UDP information
        elif packet.haslayer(UDP):
            udp = packet[UDP]

            print("Source Port     :", udp.sport)
            print("Destination Port:", udp.dport)

    # Other packet types
    else:
        print("Protocol        :", "Non-IP packet")

    # Display payload if available
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        print("Payload Size    :", len(payload), "bytes")

        print("\nPayload (Raw):")
        print(payload)

        try:
            decoded_payload = payload.decode(
                "utf-8",
                errors="ignore"
            )

            if decoded_payload.strip():
                print("\nPayload (Decoded):")
                print(decoded_payload)
            else:
                print(
                    "\nPayload (Decoded): "
                    "<Binary or Encrypted Data>"
                )

        except Exception:
            print("\nUnable to decode payload.")

    else:
        print("Payload         :", "None")

    # Display packet size
    print("\nPacket Size     :", len(packet), "bytes")

    print("=" * 70)
    print()


# Start packet sniffing
print("=" * 70)
print("       CODEALPHA - BASIC NETWORK SNIFFER")
print("=" * 70)
print("Status: Listening for network packets...")
print("Press CTRL + C to stop.\n")


try:
    sniff(prn=process_packet, store=False)

except KeyboardInterrupt:
    print("\n\nSniffer stopped successfully.")
