import argparse
from scapy.all import rdpcap
import pandas as pd
import os
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName





def load_pcap(file_path):
    """
    Reads a PCAP file and returns all packets.
    """
    return rdpcap(file_path)

def save2csv (packet_data, csv_file):
    os.makedirs(
        os.path.dirname(csv_file),
        exist_ok=True
    )

    df = pd.DataFrame(packet_data)
    df.to_csv(csv_file, index=False)
    return df

def extractSNI (packet):
    """
    return sni host name if present
    """
    if TLSClientHello not in packet:
        return None
    client_hello  = packet[TLSClientHello] 

    if not hasattr(client_hello, "ext"):
        return None
    
    for extention in client_hello.ext:
        if isinstance(extention, TLS_Ext_ServerName):
            if extention.servernames:
                return extention.servernames[0].servername.decode()
    return None


def extract_packet_info(packets):
    """
    Extract useful metadata from every IP packet.

    Parameters:
        packets : PacketList

    Returns:
        list[dict]
    """

    packet_data = []

    for index, packet in enumerate(packets, start=1):

       # make a list of tuples for each packet 
  
        if IP in packet:

            packet_data.append({
                "Packet No": index,
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "Protocol": packet.summary().split()[2],
                "Length": len(packet),
                "Timestamp": packet.time})

    return packet_data


def display_packet_info(df):

    print("=" * 60)
    print("TLSProfiler - Packet Summary")
    print("=" * 60)

    print(f"Total IP Packets: {len(df)}\n")

    print(df.head(10).to_string(index=False))


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
        df = save2csv(packet_data, "output/packet_info.csv")
        display_packet_info(df)

    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")

    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()