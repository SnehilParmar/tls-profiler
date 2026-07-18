from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import argparse
import os
import pandas as pd

from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLS


def load_pcap(file_path):
    """
    Read all packets from a PCAP file.
    """
    return rdpcap(file_path)


def get_tls_version(version):
    """
    Convert numeric TLS version into a readable string.
    """

    versions = {
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3"
    }

    return versions.get(version, f"Unknown ({version})")

def extract_sni(packet):
    """
    Extract the Server Name Indication (SNI)
    from a TLS ClientHello packet.
    """

    if TLSClientHello not in packet:
        return None

    client_hello = packet[TLSClientHello]

    if not hasattr(client_hello, "ext"):
        return None

    for extension in client_hello.ext:

        if isinstance(extension, TLS_Ext_ServerName):

            if extension.servernames:

                return extension.servernames[0].servername.decode()

    return None


def extract_tls_features(packets):
    """
    Extract useful metadata from TLS packets.
    """

    tls_data = []

    for index, packet in enumerate(packets, start=1):

        # Packet must contain both IP and TLS layers
        if IP in packet and TLS in packet:

            tls_layer = packet[TLS]

            tls_data.append({
                "Packet No": index,
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "TLS Version": get_tls_version(tls_layer.version),
                "SNI": extract_sni(packet),
                "Length": len(packet),
                "Timestamp": float(packet.time)
            })

    return tls_data


def save_to_csv(data, output_file):
    """
    Save extracted data to a CSV file.
    """

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    df = pd.DataFrame(data)

    df.to_csv(output_file, index=False)

    return df


def display_tls_info(df):
    """
    Display the first 10 TLS packets.
    """

    print("=" * 70)
    print("TLSProfiler - TLS Features")
    print("=" * 70)

    print(f"Total TLS Packets: {len(df)}\n")

    if df.empty:
        print("No TLS packets found.")
    else:
        print(df.head(10).to_string(index=False))

    print("=" * 70)


def main():

    parser = argparse.ArgumentParser(
        description="TLSProfiler - TLS Feature Extractor"
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

        tls_data = extract_tls_features(packets)

        df = save_to_csv(
            tls_data,
            "output/tls_features.csv"
        )

        display_tls_info(df)

        print("\nCSV saved to: output/tls_features.csv")

    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")

    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()