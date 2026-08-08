from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from datetime import datetime

# Dictionary to convert protocol numbers into readable names
PROTOCOLS= {
   1: "ICMP",
   2: "IGMP",
   6: "TCP",
   17: "UDP",
   41: "IPv6",
   47: "GRE",
   50: "ESP",
   51: "AH",
   89: "OSPF"
}

def process_packet(packet):
   print("=" * 70)

    #Display current time
   print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

   #checks if packet contains an ip layer
   if packet.haslayer(IP):
      ip = packet[IP]

      print("Source IP     :", ip.src)
      print("Destination IP:", ip.dst)

      #convert protocol numbers to names
      protocol_name = PROTOCOLS.get(ip.proto, f"unknown ({ip.proto})")
      print("Protocol         :", protocol_name)

      #TCP information
      if packet.haslayer(TCP):
         tcp = packet[TCP]
         print("Source Port     :", tcp.sport)
         print("Destination Port:",tcp.dport)
    
      #UDP information
      elif packet.haslayer(UDP):
         udp = packet[UDP]
         print("Source Port     :", udp.sport)
         print("Destination Port:", udp.dport)
         
      
      #ICMP information
      elif packet.haslayer(ICMP):
         icmp = packet[ICMP]
         print("ICMP Type       :", icmp.type)
         print("ICMP Code       :", icmp.code)
    
         
      else:
         print("Non-IP Packet")

      #Display payload if available
   if packet.haslayer(Raw):
        payload = packet[Raw].load
        payload_size = (len(payload))
        print("Payload Size     :", payload_size, "bytes")
        print("\nPayload (Raw):")
        print(payload)
         

   try:
        decoded_payload = payload.decode("utf-8", errors="ignore")

        if decoded_payload.strip():
              print("\nPayload (Decoded):")
              print(decoded_payload)
        else:
              print("\n Payload (Decoded): <Encrypted or Binary Data>")
       
   except Exception:
         print("Unable to decode payload.")
   else:
        print("\nPacket Size        :", len(packet), "bytes")
        print("=" * 70)
        print()


#Start packet sniffing
print("=" * 70)
print("      CODEALPHA-BASIC NETWORK SNIFFER")
print("=" * 70)
print("Status: Listening for network packets...")
print("press CTRL + C to stop.\n")

try:
    sniff(prn=process_packet, store=False)

except KeyboardInterrupt:
      print("\n\nSniffer stopped successfully.")