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


import hashlib
import csv
import json 
import argparse
import datetime
from pprint import pprint
from scapy.all import rdpcap, load_layer
from scapy.layers.tls.handshake import TLSClientHello , TLSServerHello

load_layer("tls")

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa

}


def compute_ja3 (ch):

    version = ch.version
    ciphers = [i for i in ch.ciphers if i not in GREASE_VALUES]
    ext_types, elleptic_curves, ec_point_format = [], [], []

    if ch.ext:
        for ext in ch.ext:
            if ext.type in GREASE_VALUES:
                continue
            ext_types.append(ext.type)
            if ext.type == 10:
                curves = [i for i in ext.groups if i not in GREASE_VALUES]
                elleptic_curves = curves
            
            elif ext.type == 11:
                ec_point_format = list(ext.ecpl)


    ja3_string = ','.join(
        [str(version),
        '-'.join(map(str, ciphers)),
        '-'.join(map(str, ext_types)),
        '-'.join(map(str, elleptic_curves)),
        '-'.join(map(str, ec_point_format))]
    )

    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()


    return ja3_string, ja3_hash



def get_features (pkt):
    ch = pkt[TLSClientHello]
    res = {}
    res["source_ip"] = pkt["IP"].src if pkt.haslayer("IP") else None
    res["dest_ip"] = pkt["IP"].dst if pkt.haslayer("IP") else None
    res["ttl"] = pkt["IP"].ttl if pkt.haslayer("IP") else None
    res["src_port"] = pkt["TCP"].sport if pkt.haslayer("TCP") else None
    res["dst_port"] = pkt["TCP"].dport if pkt.haslayer("TCP") else None

    # tls versions
    res["tls_version"] = ch.version

    # ciphers
    clean_ciphers  = [i for i in ch.ciphers if i not in GREASE_VALUES]
    res["ciphers"] = clean_ciphers
    res["no_of_cipher"] = len(clean_ciphers)

    # extentions
    if ch.ext:
        extentions = ch.ext
    # res["extlen"] = ch.extlen
    res["no_of_extentions"] = len(extentions)

    for ext in ch.ext:
        if ext.type == 0:   #sni extraction
            try:
                sni = ext.servernames[0].servername.decode()
            except Exception:
                pass
        if ext.type == 16:
            alpn = ext.protocols
            res["alpn"] = alpn
        else:
            res["alpn"] = 'na'
            

    res["sni"] = sni
    jaa3 = compute_ja3 (ch)
    res["ja3_str"] = jaa3[0]
    res["ja3_hash"] = jaa3[1]

    # res["extlen"] = ch.extlen
    # res["extlen"] = ch.extlen


    return res



if __name__ == "__main__":

    packets = rdpcap("2026-02-28-traffic-analysis-exercise.pcap")
    count = 0

    for pkt in packets:
        if pkt.haslayer(TLSClientHello):
            print(count, ": ", end = "")
            print(pkt.summary(), "="*22)
            pprint(get_features(pkt))
        count+=1

    pass

