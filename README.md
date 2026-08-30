# Basic Network Sniffer

A Python-based network packet sniffer developed as part of the **CodeAlpha Cyber Security Internship**. This tool captures live network traffic and displays useful packet information such as source and destination IP addresses, protocols, ports, payloads, and packet sizes using the **Scapy** library.

---

## Features

* Capture live network packets
* Display source and destination IP addresses
* Identify network protocols (TCP, UDP, ICMP)
* Display source and destination port numbers
* Show packet payload (raw and decoded when possible)
* Display payload size
* Display packet size
* Display timestamp for every captured packet
* Stop packet capture with `Ctrl + C`

---

## Technologies Used

* Python 3
* Scapy
* Npcap (Windows)

---

## Project Structure

```text
Basic_Network_Sniffer/
│
├── basic_network_sniffer.py
├── README.md
├── requirements.txt
└── screenshots/
```

---

## 📋 Requirements

* Python 3.10 or later
* Scapy
* Npcap (Windows users)

Install Scapy using:

```bash
py -m pip install scapy
```

Download and install Npcap from:

https://npcap.com/

---

## 🚀 How to Run

Clone the repository:

```bash
git clone https://github.com/Jaynium-7/Basic_Network_Sniffer.git
```

Navigate to the project folder:

```bash
cd Basic_Network_Sniffer
```

Run the program:

```bash
py basic_network_sniffer.py
```

Stop packet capture by pressing:

```text
CTRL + C
```

---

## 📷 Sample Output

```text
======================================================================
Time             : 2026-08-06 11:50:21
Source IP        : 192.168.xx.xx
Destination IP   : 142.xx.xx.xx
Protocol         : TCP
Source Port      : 53144
Destination Port : 443

Payload Size     : 517 bytes

Payload (Raw):
b'\x17\x03\x03...'

Payload (Decoded):
<Encrypted or Binary Data>

Packet Size      : 591 bytes
======================================================================
```

---

## 📖 Understanding the Output

### Source IP

The IP address of the device that sent the packet.

### Destination IP

The IP address of the device receiving the packet.

### Protocol

The communication protocol used by the packet (such as TCP, UDP, or ICMP).

### Source Port

The port number used by the sender.

### Destination Port

The port number used by the receiving application.

### Payload

The actual data carried inside the packet. For encrypted HTTPS traffic, the payload cannot be read because it is protected by TLS encryption.

### Payload Size

The size of the payload in bytes.

### Packet Size

The total size of the packet, including headers and payload.

---

## Limitations

* HTTPS traffic is encrypted, so payloads are not readable.
* The application analyzes packets but does not decrypt encrypted network traffic.
* Administrator privileges may be required on some operating systems to capture packets.

---

## What I Learned

During this project I gained practical experience with:

* Network packet capture
* Packet analysis
* TCP/IP networking
* Python programming
* Scapy library
* Protocol identification
* Network payload inspection
* Basic cybersecurity and network monitoring concepts

---

## Author
Joseph Victor Ese-Osa

Passionate about web&network security, vulnerability assessment, and continuous learning in cybersecurity.

---

## License

This project is intended for educational purposes as part of the CodeAlpha Cyber Security Internship.

