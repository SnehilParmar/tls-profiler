"""
TLS Behavioral Profiling — Feature Extractor
Extracts handshake metadata, JA3, TCP/IP features from PCAP or live capture.
Usage:
    python tls_feature_extractor.py --pcap yourfile.pcap
    python tls_feature_extractor.py --live --iface "\\Device\\NPF_{...}"
    python tls_feature_extractor.py --live --iface "\\Device\\NPF_{...}" --out results.csv
"""

import hashlib
import csv
import json
import argparse
import datetime
from scapy.all import rdpcap, sniff, load_layer
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

load_layer("tls")

# ── Lookup Tables ─────────────────────────────────────────────────────────────

TLS_VERSIONS = {
    0x0301: "TLS_1.0",
    0x0302: "TLS_1.1",
    0x0303: "TLS_1.2",
    0x0304: "TLS_1.3",
}

EXTENSION_NAMES = {
    0:     "server_name",
    1:     "max_fragment_length",
    5:     "status_request",
    10:    "supported_groups",
    11:    "ec_point_formats",
    13:    "signature_algorithms",
    16:    "application_layer_protocol_negotiation",
    17:    "status_request_v2",
    18:    "signed_certificate_timestamp",
    21:    "padding",
    23:    "session_ticket",
    35:    "session_ticket_tls",
    43:    "supported_versions",
    44:    "cookie",
    45:    "psk_key_exchange_modes",
    51:    "key_share",
    65281: "renegotiation_info",
}

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

# ── JA3 Computation ───────────────────────────────────────────────────────────

def compute_ja3(ch):
    """
    JA3 = MD5( TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats )
    GREASE values are filtered out per spec.
    """
    version = ch.version

    ciphers = [c for c in ch.ciphers if c not in GREASE_VALUES]

    ext_types, elliptic_curves, ec_point_formats = [], [], []

    if ch.ext:
        for ext in ch.ext:
            if ext.type in GREASE_VALUES:
                continue
            ext_types.append(ext.type)

            # Supported groups (elliptic curves)
            if ext.type == 10:
                try:
                    curves = [g for g in ext.groups if g not in GREASE_VALUES]
                    elliptic_curves.extend(curves)
                except Exception:
                    pass

            # EC point formats
            if ext.type == 11:
                try:
                    ec_point_formats.extend(ext.ecpl)
                except Exception:
                    pass

    ja3_str = ",".join([
        str(version),
        "-".join(map(str, ciphers)),
        "-".join(map(str, ext_types)),
        "-".join(map(str, elliptic_curves)),
        "-".join(map(str, ec_point_formats)),
    ])

    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
    return ja3_str, ja3_hash


# ── Feature Extraction ────────────────────────────────────────────────────────

def extract_client_hello_features(pkt):
    """Extract all ClientHello metadata."""
    ch = pkt[TLSClientHello]
    features = {}

    # ── Source/Destination ──
    features["src_ip"]   = pkt["IP"].src   if pkt.haslayer("IP") else None
    features["dst_ip"]   = pkt["IP"].dst   if pkt.haslayer("IP") else None
    features["src_port"] = pkt["TCP"].sport if pkt.haslayer("TCP") else None
    features["dst_port"] = pkt["TCP"].dport if pkt.haslayer("TCP") else None
    features["timestamp"] = datetime.datetime.now().isoformat()

    # ── TLS Version ──
    features["tls_version_offered"] = TLS_VERSIONS.get(ch.version, hex(ch.version))
    features["tls_version_raw"]     = ch.version

    # ── Cipher Suites ──
    clean_ciphers = [c for c in ch.ciphers if c not in GREASE_VALUES]
    features["cipher_suites"]       = clean_ciphers
    features["cipher_count"]        = len(clean_ciphers)
    features["cipher_suite_string"] = "-".join(map(str, clean_ciphers))

    # ── Session ──
    features["session_id_length"] = len(ch.sid) if ch.sid else 0

    # ── Extensions ──
    ext_types, alpn_protocols, supported_groups = [], [], []
    sni = None
    has_session_ticket      = False
    has_extended_master_sec = False
    has_encrypt_then_mac    = False

    if ch.ext:
        for ext in ch.ext:
            if ext.type in GREASE_VALUES:
                continue
            ext_types.append(ext.type)

            if ext.type == 0:   # SNI
                try:
                    sni = ext.servernames[0].servername.decode()
                except Exception:
                    pass

            elif ext.type == 16:  # ALPN
                try:
                    alpn_protocols = [p.protocol_name.decode() for p in ext.protocol_name_list]
                except Exception:
                    pass

            elif ext.type == 10:  # Supported groups
                try:
                    supported_groups = [g for g in ext.groups if g not in GREASE_VALUES]
                except Exception:
                    pass

            elif ext.type in (23, 35):  # Session ticket
                has_session_ticket = True

            elif ext.type == 23:  # Extended master secret
                has_extended_master_sec = True

            elif ext.type == 22:  # Encrypt-then-MAC
                has_encrypt_then_mac = True

    features["sni"]                     = sni
    features["alpn_protocols"]          = alpn_protocols
    features["has_alpn"]                = len(alpn_protocols) > 0
    features["alpn_string"]             = "-".join(alpn_protocols)
    features["extensions_list"]         = ext_types
    features["extension_count"]         = len(ext_types)
    features["extension_string"]        = "-".join(map(str, ext_types))
    features["supported_groups"]        = supported_groups
    features["supported_groups_string"] = "-".join(map(str, supported_groups))
    features["has_session_ticket"]      = has_session_ticket
    features["has_extended_master_sec"] = has_extended_master_sec
    features["has_encrypt_then_mac"]    = has_encrypt_then_mac

    # ── JA3 ──
    ja3_str, ja3_hash = compute_ja3(ch)
    features["ja3_string"] = ja3_str
    features["ja3_hash"]   = ja3_hash

    return features


def extract_tcp_ip_features(pkt):
    """Extract TCP/IP layer features for OS fingerprinting."""
    features = {}

    if pkt.haslayer("IP"):
        features["ttl"]            = pkt["IP"].ttl
        features["ip_flags"]       = str(pkt["IP"].flags)
        features["ip_total_length"]= pkt["IP"].len

    if pkt.haslayer("TCP"):
        features["tcp_window_size"] = pkt["TCP"].window
        features["tcp_flags"]       = str(pkt["TCP"].flags)
        features["tcp_seq"]         = pkt["TCP"].seq
        features["packet_size"]     = len(pkt)

    # OS guess from TTL
    ttl = features.get("ttl", 0)
    if ttl >= 120:
        features["os_guess"] = "Windows"
    elif ttl >= 60:
        features["os_guess"] = "Linux/Mac"
    else:
        features["os_guess"] = "Unknown"

    return features


def extract_server_hello_features(pkt):
    """Extract ServerHello metadata."""
    sh = pkt[TLSServerHello]
    features = {}

    features["server_ip"]           = pkt["IP"].src if pkt.haslayer("IP") else None
    features["chosen_cipher"]       = sh.cipher
    features["chosen_cipher_hex"]   = hex(sh.cipher)
    features["server_tls_version"]  = TLS_VERSIONS.get(sh.version, hex(sh.version))

    return features


# ── Connection Tracker ────────────────────────────────────────────────────────

class ConnectionTracker:
    """Tracks per-connection state to pair ClientHello with ServerHello."""

    def __init__(self):
        self.pending   = {}   # key: (src_ip, src_port, dst_ip) → client features
        self.completed = []   # list of fully merged connection records

    def add_client_hello(self, pkt):
        client_f = extract_client_hello_features(pkt)
        tcp_ip_f = extract_tcp_ip_features(pkt)
        merged   = {**client_f, **tcp_ip_f}

        key = (client_f["src_ip"], client_f["src_port"], client_f["dst_ip"])
        self.pending[key] = merged
        return merged

    def add_server_hello(self, pkt):
        server_f = extract_server_hello_features(pkt)

        # Match to pending ClientHello by reversing the key
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            key = (pkt["IP"].dst, pkt["TCP"].dport, pkt["IP"].src)
            if key in self.pending:
                record = {**self.pending.pop(key), **server_f}
                self.completed.append(record)
                return record

        return server_f


# ── Output Helpers ────────────────────────────────────────────────────────────

FLAT_FIELDS = [
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
    "sni", "tls_version_offered", "cipher_count", "cipher_suite_string",
    "extension_count", "extension_string", "has_alpn", "alpn_string",
    "supported_groups_string", "has_session_ticket",
    "ja3_hash", "ja3_string",
    "ttl", "os_guess", "tcp_window_size", "ip_total_length",
    "chosen_cipher_hex", "server_tls_version",
]

def print_record(record, verbose=False):
    print("\n" + "="*60)
    print(f"  {record.get('src_ip')}:{record.get('src_port')} → {record.get('dst_ip')}:{record.get('dst_port')}")
    print(f"  SNI            : {record.get('sni', 'N/A')}")
    print(f"  TLS Version    : {record.get('tls_version_offered')}")
    print(f"  ALPN           : {record.get('alpn_string', 'none')}")
    print(f"  Ciphers        : {record.get('cipher_count')} offered")
    print(f"  Extensions     : {record.get('extension_count')}")
    print(f"  Session Ticket : {record.get('has_session_ticket')}")
    print(f"  JA3            : {record.get('ja3_hash')}")
    print(f"  TTL            : {record.get('ttl')}  ({record.get('os_guess')})")
    print(f"  TCP Window     : {record.get('tcp_window_size')}")
    if record.get("chosen_cipher_hex"):
        print(f"  Chosen Cipher  : {record.get('chosen_cipher_hex')} ({record.get('server_tls_version')})")
    if verbose:
        print(f"  JA3 String     : {record.get('ja3_string')}")
        print(f"  Cipher List    : {record.get('cipher_suite_string')}")
        print(f"  Extensions     : {record.get('extension_string')}")


def save_csv(records, path):
    if not records:
        print("[!] No records to save.")
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FLAT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print(f"\n[✓] Saved {len(records)} records → {path}")


def save_json(records, path):
    # Convert lists to strings for JSON serialization
    serializable = []
    for r in records:
        row = dict(r)
        for k, v in row.items():
            if isinstance(v, list):
                row[k] = str(v)
        serializable.append(row)
    with open(path, "w") as f:
        json.dump(serializable, f, indent=2)
    print(f"[✓] Saved {len(records)} records → {path}")


# ── Main Logic ────────────────────────────────────────────────────────────────

def process_packets(packets, verbose=False):
    tracker = ConnectionTracker()
    all_records = []

    for pkt in packets:
        if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
            continue

        if pkt.haslayer(TLSClientHello):
            record = tracker.add_client_hello(pkt)
            print_record(record, verbose)
            all_records.append(record)

        elif pkt.haslayer(TLSServerHello):
            tracker.add_server_hello(pkt)

    # Merge completed (paired) records back
    for completed in tracker.completed:
        # Update matching record in all_records
        for i, r in enumerate(all_records):
            if (r.get("src_ip") == completed.get("src_ip") and
                r.get("src_port") == completed.get("src_port")):
                all_records[i] = completed
                break

    return all_records


def run_pcap(pcap_path, out=None, verbose=False):
    print(f"[*] Loading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f"[*] {len(packets)} packets loaded\n")
    records = process_packets(packets, verbose)
    print(f"\n[*] Total connections: {len(records)}")
    if out:
        if out.endswith(".json"):
            save_json(records, out)
        else:
            save_csv(records, out)
    return records


def run_live(iface, out=None, verbose=False, count=0, timeout=None):
    tracker = ConnectionTracker()
    all_records = []

    def live_process(pkt):
        if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
            return
        if pkt.haslayer(TLSClientHello):
            record = tracker.add_client_hello(pkt)
            print_record(record, verbose)
            all_records.append(record)
        elif pkt.haslayer(TLSServerHello):
            tracker.add_server_hello(pkt)

    print(f"[*] Live capture on {iface} — Ctrl+C to stop\n")
    try:
        sniff(
            iface=iface,
            filter="tcp port 443",
            prn=live_process,
            store=0,
            count=count,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        pass

    print(f"\n[*] Captured {len(all_records)} connections")
    if out:
        if out.endswith(".json"):
            save_json(all_records, out)
        else:
            save_csv(all_records, out)
    return all_records


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Behavioral Profiling — Feature Extractor")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pcap",  help="Path to .pcap file")
    mode.add_argument("--live",  action="store_true", help="Live capture mode")
    parser.add_argument("--iface",   help="Network interface for live capture")
    parser.add_argument("--out",     help="Output file (.csv or .json)")
    parser.add_argument("--verbose", action="store_true", help="Print JA3 strings and cipher lists")
    parser.add_argument("--count",   type=int, default=0, help="Packet count limit (live only)")
    parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds (live only)")
    args = parser.parse_args()

    if args.pcap:
        run_pcap(args.pcap, out=args.out, verbose=args.verbose)
    elif args.live:
        if not args.iface:
            print("[!] --iface required for live capture")
            print("    Run: python -c \"from scapy.all import IFACES; IFACES.show()\"")
        else:
            run_live(args.iface, out=args.out, verbose=args.verbose,
                     count=args.count, timeout=args.timeout)