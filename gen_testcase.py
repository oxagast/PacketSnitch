# oxagast
# use:
#   tcpdump -w ~/capture.pcap 'port 9000'
#   python3 pcap_gen_testcases.py ~/capture.pcap
# this will create a testcase directory of each destination port filled with files each
# the data section of the packets in the pcap file.  One packet is one file.  TCP header
# info is stripped.

import os
import sys
import argparse
import magic
import json
import numpy as np
from scipy.stats import entropy
import socket
import chardet
import zlib
import geoip2.database

database_path = "GeoLite2-City.mmdb"


try:
    import scapy.all as scapy
except ImportError:
    import scapy


def write_testcase(data, output_dir, pdir, index):
    if not os.path.exists(output_dir + "/" + pdir):
        os.mkdir(output_dir + "/" + pdir)
    out = open(
        output_dir + "/" + pdir + "/pcap.data_packet." + str(index) + ".dat", "wb"
    )
    out.write(data)


def write_info(output_dir, pdir, index, dt_json, pkt_json):
    out = open(
        output_dir + "/" + pdir + "/pcap.info_packet." + str(index) + ".json", "wb"
    )
    merge_json = {
        "Packet Info": json.loads(pkt_json),
        "Extra Info": json.loads(dt_json),
    }
    out.write(json.dumps(merge_json).encode())
    return merge_json


def safe_decompress(compressed_data):
    # Initialize decompressor
    dco = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)  # Handle gzip and zlib formats
    result = b""
    try:
        result = dco.decompress(compressed_data)
        result += dco.flush()
    except zlib.error as e:
        pass
    return result


def get_geoip_info(ip):
    try:
        with geoip2.database.Reader(database_path) as reader:
            response = reader.city(ip)
            return {
                "Country": response.country.name,
                "City": response.city.name,
                "Postal Code": response.postal.code,
                "Time Zone": response.location.time_zone,
            }
    except geoip2.errors.AddressNotFoundError:
        return {"Location": "Unknown"}
    except Exception as e:
        return {"Error": str(e)}


def get_datatypes(data, dport, srcip, destip):
    mime_type = magic.from_buffer(data, mime=True)
    descs = []
    dedata = ""
    compressedd = {"Decompressed": False}
    for ln in data.splitlines():
        descs.append(magic.from_buffer(ln))
        dedata = safe_decompress(ln)
        if dedata and len(dedata) > 0:
            compressedd = {
                "Decompressed data": {
                    "Decompressed Hex Encoded": dedata.hex(),
                    "Decompressed ASCII Encoded": dedata.decode(errors="ignore"),
                },
            }
    udescs = list(set(descs))
    if "empty" in udescs:
        udescs.remove("empty")
    if "data" in udescs:
        udescs.remove("data")
    if udescs == []:
        udescs = ["Unknown data type"]
    trait_struct = get_traits(data, dport, srcip, destip)
    dt = {
        "MIME Type": mime_type,
        "Decompressed": compressedd,
        "Data Types": udescs,
        "Traits": trait_struct,
    }
    return dt


def get_serv(port, protocol="tcp"):
    try:
        serv_name = socket.getservbyport(port, protocol)
        return serv_name
    except Exception:
        return "Unknown"


def get_traits(data, dport, srcip, destip):
    counts = np.bincount(list(data))
    entop = entropy(counts, base=2)
    data_len = len(data)
    protostr = get_serv(dport)
    charset = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    chars_used = len(set(data))
    uniq_chars = set(data)
    encoding = chardet.detect(data)
    loc_info_src = get_geoip_info(srcip)
    loc_info_dest = get_geoip_info(destip)
    return {
        "Shannon Entropy": entop,
        "Location Data": {
            "Source IP": loc_info_src,
            "Destination IP": loc_info_dest,
        },
        "Length": data_len,
        "Port Protcol": protostr,
        "Characters": {
            "Charset": charset,
            "Encoding": encoding,
            "Characters used": chars_used,
            "Unique characters": bytearray(list(uniq_chars)).hex(),
        },
    }


def parse_pcap(pcap_path, srcp, dstp):
    print(
        "Generating testcases based on " + sys.argv[1] + ".  This will take a while..."
    )
    s = 0
    packets = scapy.rdpcap(pcap_path)
    for p in packets:
        if p.haslayer("TCP"):
            raw_d = p["TCP"].payload.original
            sport = p["TCP"].sport
            dport = p["TCP"].dport
            dport_dir = str(dport)
            if (srcp is None or sport == srcp) and (dstp is None or dport == dstp):
                if raw_d is not None and len(raw_d) > 0:
                    write_testcase(raw_d, args.output, dport_dir, s)
                    dt_struct = get_datatypes(raw_d, dport, p["IP"].src, p["IP"].dst)
                    pkt_struct = {
                        "Packet Processed": int(s),
                        "IP": {
                            "Source IP": str(p["IP"].src),
                            "Destination IP": str(p["IP"].dst),
                            "IP Checksum": int(p["IP"].chksum),
                        },
                        "TCP": {
                            "Source port": int(sport),
                            "Destination port": int(dport),
                            "TCP checksum": int(p["TCP"].chksum),
                            "Urgent flag": bool(p["TCP"].urgptr),
                            "TCP flags": str(p["TCP"].flags),
                            "Options": list(p["TCP"].options),
                        },
                        "Raw data": {
                            "Payload": {
                                "Hex Encoded": raw_d.hex(),
                                "ASCII Encoded": raw_d.decode(errors="ignore"),
                            },
                            "Packet": bytes(p).hex(),
                        },
                    }
                    write_info(
                        args.output,
                        dport_dir,
                        s,
                        json.dumps(dt_struct).encode(),
                        json.dumps(pkt_struct).encode(),
                    )
                    s = s + 1
    print("Generated " + str(s) + " testcases.", file=sys.stderr)


parser = argparse.ArgumentParser(
    description="Generate payload testcases from a .pcap file.", prog="gen_testcases"
)
parser.add_argument("pcap_file", help="The .pcap file to parse.")
parser.add_argument(
    "-o",
    "--output",
    help="The output directory for the testcases.",
    default="testcases",
)
parser.add_argument(
    "-s",
    "--source-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
args = parser.parse_args()
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(args.output):
    os.mkdir(args.output)
print(parse_pcap(args.pcap_file, args.source_port, args.dest_port))
print("Done.", file=sys.stderr)
sys.exit(0)
