from scapy.all import rdpcap
from scapy.layers.inet import TCP

packets = rdpcap("youtube.pcap")

https_packets = []

for packet in packets:

    if TCP in packet:

        if packet[TCP].sport == 443 or packet[TCP].dport == 443:
            https_packets.append(packet)

print("HTTPS Packets:", len(https_packets))

print("\nFirst HTTPS Packet:\n")

if len(https_packets) > 0:
    https_packets[0].show()