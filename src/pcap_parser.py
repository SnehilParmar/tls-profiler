import argparse
from scapy.all import rdpcap
from scapy.layers.inet import IP

def load_pcap(file_path):
    """
    Reads a PCAP file and returns all packets.
    """
    return rdpcap(file_path)





def extract_packet_info(packets):
    """
    Extract basic information from every packet.
    """

    packet_data = []

    for index, packet in enumerate(packets, start=1):

       # make a list of tuples for each packet 
  
        if IP in packet:

            packet_data.append({
                "Packet No": index,
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "Protocol": packet.lastlayer().name,
                "Length": len(packet)


            })

    return packet_data


def display_summary(packet_data):

    print("=" * 60)
    print("TLSProfiler - Packet Summary")
    print("=" * 60)

    print(f"Total IP Packets: {len(packet_data)}\n")

    for packet in packet_data[:10]:
        print(packet)


def main():

    parser = argparse.ArgumentParser(
        description="TLSProfiler PCAP Parser"
    )

    parser.add_argument(
        "pcap",
        nargs="?",
        default="captures/reddit.pcap",
        help="Path to the PCAP file"
    )

    args = parser.parse_args()

    try:

        packets = load_pcap(args.pcap)

        packet_data = extract_packet_info(packets)
        display_summary(packet_data)

    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")

    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()