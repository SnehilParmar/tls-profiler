from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP


packets = rdpcap("youtube.pcap")

tcp_packets = 0
udp_packets = 0

for packet in packets:
    if IP in packet:
        if TCP in packet:
            tcp_packets += 1
        elif UDP in packet:
            udp_packets += 1    

print(f"TCP Packets: {tcp_packets}")
print(f"UDP Packets: {udp_packets}")


