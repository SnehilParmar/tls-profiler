import argparse
from scapy.all import rdpcap


def load_pcap(file_path):
    """
    Reads a PCAP file and returns all packets.
    """
    return rdpcap(file_path)


def display_summary(packets):
    """
    Displays basic information about the capture.
    """

    print("=" * 60)
    print("TLSProfiler - PCAP Parser")
    print("=" * 60)

    print(f"Total Packets : {len(packets)}")

    print("\nFirst 5 Packet Summaries:\n")

    for index, packet in enumerate(packets[:5], start=1):
        print(f"{index}. {packet.summary()}")

    print("=" * 60)


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

        display_summary(packets)

    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")

    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()