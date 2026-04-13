## snitch.py: Analyze pcap network captures, extract TCP packet data, and gather extra information.
#
# This script processes .pcap files, extracting TCP packet payloads and metadata, and generates
# testcases and info files for each packet. It enriches the output with MIME types, entropy,
# geoip, network class, banners, and more. Optionally, it performs active reconnaissance to
# gather additional network and server information. Summaries and final reports can be generated
# using a large language model (LLM).
#
# Features:
#   - Extracts TCP packet data and metadata from .pcap files.
#   - Writes raw payloads and info files to output directories.
#   - Determines MIME types, entropy, geoip, network class, banners, and more.
#   - Optionally performs active reconnaissance (reverse DNS, banners, SSL info, etc.).
#   - Supports multi-threaded processing for large captures.
#   - Summarizes results using LLM integration (Ollama).
#   - Outputs consolidated JSON and summary files.
#
# Usage:
#   python3 snitch.py <pcap_file> [options]
#   See command-line argument parser below for available options.
#
# Dependencies:
#   - scapy, numpy, requests, chardet, geoip2, magic, yaml, ollama, bs4, scipy, etc.
#
# Author: oxagast oxagast
# Import standard and third-party libraries for argument parsing, file handling, networking, compression, and data processing
import argparse
import csv
import json
import os
import shutil
import socket
import ssl
import sys
import textwrap
import threading
import time
import zlib
from datetime import datetime
from decimal import Decimal
import chardet
import geoip2.database
import magic
import numpy as np
import ollama
import requests
import yaml

# from tqdm import tqdm
import ipaddress
from bs4 import BeautifulSoup
from ollama import ResponseError
from scipy.stats import entropy
from concurrent.futures import ThreadPoolExecutor, as_completed

stop_event = threading.Event()

try:
    import scapy.all as scapy
except ImportError:
    import scapy

ar = "False"
nthreads = 6
nllmthreads = 5
response_length = 100
llm_model = "minimax-m2.5:cloud"
use_llm = False

# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
summaries = []
summaries_lock = threading.Lock()
all_info = []
all_info_lock = threading.Lock()

# Concurrency controls
llm_call_lock = threading.Semaphore(nllmthreads)  # cap simultaneous LLM calls

hostoutfile = "hosts.json"
cur_dir = os.getcwd()
script_dir = os.path.dirname(os.path.realpath(__file__)) + "/"

# --- Lookup tables loaded once at startup (see init_lookup_tables()) ---
# Keyed (port_int, "tcp"/"udp") -> description string
port_desc_map: dict = {}
# Keyed by uppercase MAC prefix (e.g. "00:1A:2B") -> vendor name
mac_vendor_map: dict = {}

# --- GeoIP reader opened once and reused across all packets ---
# Protected by geoip_cache_lock for the cache; the Reader itself is thread-safe.
geoip_reader = None
geoip_cache: dict = {}
geoip_cache_lock = threading.Lock()

# --- Banner cache: (ip, port) -> banner dict, avoids redundant socket probes ---
checked_ips: dict = {}
checked_ips_lock = threading.Lock()


def llm_query(packet_infos):
    """
    Query a large language model (LLM) with packet information for summarization.
    Handles retries and concurrency limits. Appends responses to the global summaries list.
    """
    with llm_call_lock:
        try:
            if ollama and use_llm and packet_infos:
                # Attempt up to 2 times with exponential backoff; halve the payload on each retry
                for resc in range(2):
                    try:
                        res = ollama.generate(
                            model=llm_model,
                            prompt=f"Tell me what you can about the following network capture (encoded in json, from pcap), its payload, and any interesting or unusual traits... respond with a single paragraph around {response_length} words: {packet_infos}",
                        )
                        if res and "response" in res:
                            # Protect list append from concurrent thread writes
                            with summaries_lock:
                                summaries.append(res["response"])
                        else:
                            return {"Summary": ""}
                    except ResponseError as re:
                        if verbose >= 2:
                            print(
                                f"LLM API response error (attempt {resc + 1}/3): {str(re)}",
                                file=sys.stderr,
                            )
                        time.sleep(2**resc)  # Exponential backoff
                        packet_infos = packet_infos[
                            : int(len(packet_infos) / (2**resc))
                        ]
                        if verbose >= 1:
                            print(
                                f"Retrying with truncated (halved) string (attempt {resc + 1}/3)...",
                                file=sys.stderr,
                            )
            else:
                return {"Summary": "LLM integration not enabled"}
        except Exception as e:
            return {"Summary": "LLM integration error: " + str(e)}


def config_loader(filename="conf.yaml"):
    """
    Load YAML configuration from the specified file.
    Exits if the file does not exist.
    """
    with open(filename, "r") as f:
        return yaml.safe_load(f)


def get_port_description(port, protocol="tcp"):
    """
    Return the IANA description for a port/protocol pair.
    Uses the port_desc_map dict loaded once at startup for O(1) lookup.
    """
    return port_desc_map.get((port, protocol), "No description available")


def reverse_dns_lookup(ip):
    """
    Perform a reverse DNS lookup for the given IP address.
    Returns a dictionary with resolution status and hostnames or error.
    """

    try:
        dat = socket.gethostbyaddr(ip)
        return (
            {"Resolved": True, "Hostnames": dat}
            if dat and len(dat) > 0
            else {"Resolved": False, "Error": "No PTR record found"}
        )
    except Exception as e:
        return {
            "Resolved": False,
            "Error": "Address resolution error: " + str(e),
        }


def get_serv_banner(ip, port, t, hostname):
    """
    Retrieve the service banner, SSL certificate, and page title for a given IP and port.
    Uses a dict cache keyed by (ip, port) to avoid redundant network probes.
    Handles both HTTP and HTTPS. Returns a dict with banner, page title, and encryption data.
    """

    cache_key = (ip, port)
    # Fast O(1) cache hit check before doing any network work
    with checked_ips_lock:
        if cache_key in checked_ips:
            return checked_ips[cache_key]

    socket_cert = "Unavailable"
    encrypted_with = "N/A"
    ssl_version = "N/A"
    pt = "N/A"
    bannerdata = {}
    # Get page title for HTTP/HTTPS ports
    try:
        if port == 443:
            pt = get_page_title("https://" + hostname + ":" + str(port), t)
        else:
            pt = get_page_title("http://" + hostname + ":" + str(port), t)
    except Exception:
        pt = "N/A"
    # Try to fetch SSL certificate info (ignore errors; port may not support TLS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_sock = context.wrap_socket(s, server_hostname=ip)
        ssl_sock.connect((ip, port))
        if ssl_sock:
            socket_cert = ssl_sock.getpeercert()
            encrypted_with = ssl_sock.cipher()
            ssl_version = ssl_sock.version()
        s.close()
    except Exception:
        pass
    # Try to fetch banner from server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        if len(banner) > 0:
            bannerdata = {
                "Banner": banner,
                "Page Title": pt,
                "Encryption Data": {
                    "SSL Cert": socket_cert,
                    "SSL Version": ssl_version,
                    "Encrypted With": encrypted_with,
                }
                if ssl_version != "N/A"
                else "N/A",
            }
            s.close()
        else:
            # No passive banner; try an HTTP HEAD request as a fallback
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            if len(banner) > 0:
                bannerdata = {
                    "Banner": banner,
                    "Page Title": pt,
                    "Encryption Data": {
                        "SSL Cert": socket_cert,
                        "SSL Version": ssl_version,
                        "Encrypted With": encrypted_with,
                    }
                    if ssl_version != "N/A"
                    else "N/A",
                }
            else:
                bannerdata = {
                    "Page Title": pt,
                    "Encryption Data": {
                        "SSL Cert": socket_cert,
                        "SSL Version": ssl_version,
                        "Encrypted With": encrypted_with,
                    }
                    if ssl_version != "N/A"
                    else "N/A",
                }
    except Exception:
        bannerdata = {
            "Page Title": pt,
            "Encryption Data": {
                "SSL Cert": socket_cert,
                "SSL Version": ssl_version,
                "Encrypted With": encrypted_with,
            }
            if ssl_version != "N/A"
            else "N/A",
        }
    # Store in cache so repeated calls for the same (ip, port) are free
    with checked_ips_lock:
        checked_ips[cache_key] = bannerdata
    return bannerdata


def get_page_title(url, t):
    """
    Fetch the HTML page title from the given URL with a timeout.
    Returns the title string or "N/A" if unavailable.
    """

    try:
        requests.packages.urllib3.disable_warnings(  # ignore
            category=InsecureRequestWarning  # ignore request warning
        )  # ignore
        res = requests.get(url, timeout=t, verify=False)
        res.raise_for_status()
        cont = res.content
        soup = BeautifulSoup(cont, "html.parser")
        return soup.title.string if soup.title else "N/A"
    except Exception:
        return "N/A"


def write_testcase(data, output_dir, pdir, index):
    """
    Write raw packet payload bytes to a testcase file.
    Creates the per-port sub-directory on first use; errors there are non-fatal.
    Uses a context manager so the file descriptor is always released.
    """
    dest_dir = output_dir + "/" + pdir
    if not os.path.exists(dest_dir):
        try:
            os.mkdir(dest_dir)
        except Exception:
            print("Error: Nonfatal: Could not create minor dir.")
    with open(dest_dir + "/pcap.data_packet." + str(index) + ".dat", "wb") as out:
        out.write(data)


def join_info(output_dir, pdir, index, dt_json, pkt_json, host):
    """
    Merge packet-level info with extra analysis info and write as a JSON file.
    Thread-safe: uses all_info_lock when appending to the shared all_info list.
    """
    merge_json = {
        "Packet Info": json.loads(pkt_json),
        "Extra Info": json.loads(dt_json),
    }
    path = output_dir + "/" + pdir + "/pcap.info_packet." + str(index) + ".json"
    with open(path, "wb+") as out:
        out.write(json.dumps(merge_json).encode())
    if verbose >= 2:
        print(json.dumps(merge_json, indent=2))
    # Protect the shared list from concurrent thread writes
    with all_info_lock:
        all_info.append({"Host": host, "Packet": merge_json})
    return merge_json


by_host_dict = {}


def sort_and_index_packets(by_host_dict):
    for host, packets in by_host_dict.items():
        # Skip empty or invalid entries
        if not packets:
            continue

        # Sort packets by timestamp
        packets.sort(
            key=lambda p: datetime.strptime(
                p["Packet Info"]["Packet Timestamp"], "%Y-%m-%d %H:%M:%S.%f"
            )
        )

        # Add chronological index
        for i, pkt in enumerate(packets, start=1):
            pkt["Packet Info"]["Index"] = i

    return by_host_dict


def by_host(out, final_summary):
    """
    Organise all_info entries by destination host and write the result to hosts.json.
    Bug fix: the original code created the empty list but then only appended on the
    *else* branch, silently dropping the first packet for every unique host.
    Now every packet is always appended.
    """
    global by_host_dict
    for entry in all_info:
        host = entry.get("Host")
        if host not in by_host_dict:
            by_host_dict[host] = []
        # Always append — previously the first packet per host was lost
        by_host_dict[host].append(entry.get("Packet"))

    by_host_dict = sort_and_index_packets(by_host_dict)

    # Write the consolidated hosts file; use a context manager to guarantee flush/close
    with open(out + "/" + hostoutfile, "w+", encoding="utf-8") as f:
        f.write(
            json.dumps({"Host": by_host_dict, "Final Summary": final_summary}, indent=2)
        )


def get_netclass(ip):
    """
    Determine the network class (A, B, C, or Unknown) of an IPv4 address.
    """
    ip_obj = ipaddress.ip_address(ip)
    # Get the first octet
    first_octet = int(str(ip_obj).split(".")[0])
    # Determine the class
    if 1 <= first_octet <= 127:
        return "A"
    elif 128 <= first_octet <= 191:
        return "B"
    elif 192 <= first_octet <= 223:
        return "C"
    elif 224 <= first_octet <= 239:
        return "D"
    elif 240 <= first_octet <= 255:
        return "E"
    else:
        return "Invalid IP"


def safe_decompress(compressed_data):
    """
    Safely decompress gzip or zlib-compressed data.
    Returns the decompressed bytes, or empty bytes on error.
    """

    # Initialize decompressor
    # Handle gzip and zlib formats
    dcomper = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    result = b""
    try:
        result = dcomper.decompress(compressed_data)
        result += dcomper.flush()
    except zlib.error:
        pass
    return result


def get_geoip_info(ip, sord):
    """
    Look up GeoIP information (country, city, postal code, timezone) for an IP address.
    Uses geoip_reader opened once at startup and a per-session cache dict so that
    repeated lookups for the same IP cost nothing beyond a dict read.
    Returns a dictionary with location data or error message.
    """
    if geoip_reader is None:
        return {"Location": "Error: GeoIP database not found!"}

    # Check cache first (lock only for the brief check/insert, not for the DB query)
    cache_key = (ip, sord)
    with geoip_cache_lock:
        if cache_key in geoip_cache:
            return geoip_cache[cache_key]

    try:
        response = geoip_reader.city(ip)
        if sord == "src":
            result = {
                "Country": response.country.name,
                "loc.src.country": response.country.name,
                "City": response.city.name,
                "loc.src.city": response.city.name,
                "Postal Code": response.postal.code,  # type: ignore
                "loc.src.postal": response.postal.code,  # type: ignore
                "Time Zone": response.location.time_zone,  # type: ignore
                "loc.src.tz": response.location.time_zone,  # type: ignore
                "loc.src.timezone": response.location.time_zone,  # type: ignore
            }
        else:  # sord == "dst"
            result = {
                "Country": response.country.name,
                "loc.dst.country": response.country.name,
                "City": response.city.name,
                "loc.dst.city": response.city.name,
                "Postal Code": response.postal.code,  # type: ignore
                "loc.dst.postal": response.postal.code,  # type: ignore
                "Time Zone": response.location.time_zone,  # type: ignore
                "loc.dst.tz": response.location.time_zone,  # type: ignore
                "loc.dst.timezone": response.location.time_zone,  # type: ignore
            }
    except geoip2.errors.AddressNotFoundError:  # type: ignore
        result = {"Location": "Localnet"}
    except Exception as e:
        result = {"Location": "Error: " + str(e)}

    # Store in cache so subsequent calls for this IP are instant
    with geoip_cache_lock:
        geoip_cache[cache_key] = result
    return result


def get_datatypes(data, dport, srcip, destip, tmout):
    """
    Analyze data to determine MIME type, decompress if possible, and extract traits.
    Returns a dictionary with MIME type, decompression info, data types, and traits.
    """
    mime_type = magic.from_buffer(data, mime=True)
    descs = []
    dedata = ""
    decom = {"Decompressed": False}
    for ln in data.splitlines():
        descs.append(magic.from_buffer(ln))
        dedata = safe_decompress(ln)
        if dedata and len(dedata) > 0:
            decom = {
                "Decompressed data": {
                    "Decompressed Hex Encoded": dedata.hex(),
                    "payload.decompressed.hex": dedata.hex(),
                    "Decompressed ASCII Encoded": dedata.decode(errors="ignore"),
                    "payload.decompressed.ascii": dedata.decode(errors="ignore"),
                },
            }
    udescs = list(set(descs))
    if "empty" in udescs:
        udescs.remove("empty")
    if "data" in udescs:
        udescs.remove("data")
    if udescs == []:
        udescs = ["Unknown data type"]
    trait_struct = get_traits(data, dport, srcip, destip, tmout)
    dt = {
        "MIME Type": mime_type,
        "payload.mime": mime_type,
        "Decompressed": decom,
        "payload.decompressed": decom,
        "Data Types": udescs,
        "Traits": trait_struct,
    }
    return dt


def get_serv(port, protocol="tcp"):
    """
    Return the service name for a given port and protocol using the system's services database.
    """

    try:
        serv_name = socket.getservbyport(port, protocol)
        return serv_name
    except Exception:
        return "Unknown"


def get_traits(data, dport, srcip, destip, timeout):
    """
    Analyze data for entropy, charset, encoding, and network/server traits.
    Returns a dictionary with entropy, network data, length, server info, and character info.
    """

    counts = np.bincount(list(data))
    entop = entropy(counts, base=2)
    data_len = len(data)
    protostr = get_serv(dport)
    charset = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    chars_used = len(set(data))
    uniq_chars = set(data)
    if ar:
        hostn = reverse_dns_lookup(destip)
    else:
        hostn = {
            "Resolved": False,
            "Error": "Active recon not performed",
            "Hostnames": [],
        }
    if ar and hostn.get("Hostnames") is not None:
        banner = get_serv_banner(
            destip,
            dport,
            timeout,
            hostn.get("Hostnames")[0]
            if hostn.get("Resolved")
            else destip,  # ignore subscript warning, it checks for resolution first
        )
    else:
        banner = "Active recon not performed"
    encoding = chardet.detect(data)
    loc_info_src = get_geoip_info(srcip, "src")
    loc_info_dest = get_geoip_info(destip, "dst")
    nc_info_src = get_netclass(srcip)
    nc_info_dest = get_netclass(destip)
    port_desc = get_port_description(dport)
    return {
        "Shannon Entropy": entop,
        "payload.entropy": entop,
        "Network Data": {
            "Source IP": {
                "Class": nc_info_src,
                "ip.src.class": nc_info_src,
                "Location": loc_info_src,
                "ip.src.location": loc_info_src,
            },
            "Destination IP": {
                "Class": nc_info_dest,
                "ip.dst.class": nc_info_dest,
                "Location": loc_info_dest,
                "ip.dst.location": loc_info_dest,
            },
            "Port Protcol": protostr,
            "tcp.proto": protostr,
            "Port Description": port_desc,
            "tcp.desc": port_desc,
            "Hostnames": hostn,
            "dns.hostnames": hostn,
        },
        "Length": data_len,
        "Server Info": banner,
        "host.banner": banner,
        "Characters": {
            "Charset": charset,
            "payload.charset": charset,
            "Encoding": encoding
            if entop <= 4.85
            else "Unavailable for high entropy data",
            "payload.encoding": encoding
            if entop <= 4.85
            else "Unavailable for high entropy data",
            "Characters used": chars_used,
            "payload.chars.used": chars_used,
            "Unique characters": bytearray(list(uniq_chars)).hex(),
        },
    }


def mac_addr_to_vendor(mac):
    """
    Return the vendor name for a MAC address.
    Uses mac_vendor_map dict loaded once at startup for O(1) prefix lookup.
    MAC prefixes are stored as the first 8 characters of the normalised address (e.g. "00:1A:2B").
    """
    prefix = mac[:8].upper()
    return mac_vendor_map.get(prefix, "Unknown Vendor")


def packet_loop(p, pkt_index, srcp, dstp, tmout):
    """
    Process a single scapy packet: extract TCP payload, write the raw testcase file,
    gather analysis data (MIME, entropy, geoip, etc.) and merge everything into a
    single JSON output file.

    pkt_index is the 0-based position of this packet in the full capture, used as
    the filename index so files from concurrent threads do not collide.
    Returns the merged info dict, or None if the packet should be skipped.
    """
    mac_addr_src = p.src if p.haslayer("Ethernet") else "N/A"
    mac_addr_dst = p.dst if p.haslayer("Ethernet") else "N/A"
    mac_vendor_src = (
        mac_addr_to_vendor(mac_addr_src) if mac_addr_src != "N/A" else "N/A"
    )
    mac_vendor_dst = (
        mac_addr_to_vendor(mac_addr_dst) if mac_addr_dst != "N/A" else "N/A"
    )
    if not p.haslayer("IP"):
        return None
    if not p.haslayer("TCP"):
        return None

    raw_d = p["TCP"].payload.original
    sport = p["TCP"].sport
    dport = p["TCP"].dport
    dport_dir = str(dport)
    if (srcp is None or sport == srcp) and (dstp is None or dport == dstp):
        if raw_d is not None and len(raw_d) > 0:
            write_testcase(raw_d, outd, dport_dir, pkt_index)
            dt_struct = get_datatypes(raw_d, dport, p["IP"].src, p["IP"].dst, tmout)
            timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            # Build TCP flag string once
            flag_data = ""
            if p["TCP"].flags.S:
                flag_data += "SYN|"
            if p["TCP"].flags.A:
                flag_data += "ACK|"
            if p["TCP"].flags.F:
                flag_data += "FIN|"
            if p["TCP"].flags.R:
                flag_data += "RST|"
            if p["TCP"].flags.P:
                flag_data += "PSH|"
            if p["TCP"].flags.U:
                flag_data += "URG|"
            if p["TCP"].flags.ECE:
                flag_data += "ECE|"
            if p["TCP"].flags.CWR:
                flag_data += "CWR|"
            if flag_data.endswith("|"):
                flag_data = flag_data[:-1]

            # Resolve geoip once per packet so we don't hit the cache (or DB) twice
            # for the same IP within a single packet.
            src_geo = get_geoip_info(p["IP"].src, "src")
            dst_geo = get_geoip_info(p["IP"].dst, "dst")
            is_local = (
                src_geo.get("Location") == "Localnet"
                and dst_geo.get("Location") == "Localnet"
            )

            pkt_struct = {
                "Packet Processed": int(pkt_index),
                "Packet Timestamp": timestamp,
                "packet.timestamp": timestamp,
                # Only include Ethernet MAC data for LAN-local traffic
                "Ethernet Frame": {
                    "MAC Source": mac_addr_src,
                    "ether.src.mac.addr": mac_addr_src,
                    "MAC Destination": mac_addr_dst,
                    "ether.dst.mac.addr": mac_addr_dst,
                    "MAC Source Vendor": mac_vendor_src,
                    "ether.src.mac.vendor": mac_vendor_src,
                    "MAC Destination Vendor": mac_vendor_dst,
                    "ether.dst.mac.vendor": mac_vendor_dst,
                }
                if is_local
                else "N/A",
                "IP": {
                    "Source IP": str(p["IP"].src),
                    "ip.src.addr": str(p["IP"].src),
                    "Destination IP": str(p["IP"].dst),
                    "ip.dst.addr": str(p["IP"].dst),
                    "IP Checksum": hex(int(p["IP"].chksum)),
                    "ip.chksum": hex(int(p["IP"].chksum)),
                    "IP layer length": int(p["IP"].len),
                    "ip.len": int(p["IP"].len),
                },
                "TCP": {
                    "Source port": int(sport),
                    "tcp.src.port": int(sport),
                    "Destination port": int(dport),
                    "tcp.dst.port": int(dport),
                    "TCP checksum": hex(int(p["TCP"].chksum)),
                    "tcp.chksum": hex(int(p["TCP"].chksum)),
                    "Urgent flag": bool(p["TCP"].urgptr),
                    "tcp.urgptr": bool(p["TCP"].urgptr),
                    "TCP Flag Data": {
                        "Flags": flag_data if flag_data else "None",
                        "tcp.flags": flag_data if flag_data else "None",
                    },
                    "Options": list(p["TCP"].options),
                    "tcp.options": list(p["TCP"].options),
                    "TCP layer length": int(p["TCP"].dataofs * 4),
                    "tcp.len": int(p["TCP"].dataofs * 4),
                    "Wire length": len(p["TCP"]),
                    "wire.len": len(p["TCP"]),
                },
                "Raw data": {
                    "Payload": {
                        "Hex Encoded": raw_d.hex(),
                        "payload.hex": raw_d.hex(),
                        "ASCII Encoded": raw_d.decode(errors="ignore"),
                        "payload.ascii": raw_d.decode(errors="ignore"),
                    },
                    "Packet": bytes(p).hex(),
                    "packet.hex": bytes(p).hex(),
                    "Payload Length": len(raw_d),
                    "payload.len": len(raw_d),
                },
            }
            # Use the non-local IP as the host key; fall back to src for LAN captures
            host_key = (
                p["IP"].dst if dst_geo.get("Location") != "Localnet" else p["IP"].src
            )
            data_back = join_info(
                outd,
                dport_dir,
                pkt_index,
                json.dumps(dt_struct).encode(),
                json.dumps(pkt_struct).encode(),
                host_key,
            )
            return data_back


def process_packet_at_index(pkt_index, srcp, dstp, tmout):
    """
    Thin wrapper used by ThreadPoolExecutor.map so we can pass a single (index, packet)
    task without pickling scapy packet objects.  The global `packets` list is already
    loaded in memory, so this is just a cheap indexed lookup + the real per-packet work.
    """
    if stop_event.is_set():
        return None
    p = packets[pkt_index]
    return packet_loop(p, pkt_index, srcp, dstp, tmout)


summaries_batch = []


def info_distiller(batch_size):
    """
    lines: iterable of input data
    worker_fn: function that takes a list (batch) and processes it
    batch_size: num:withber of items per batch
    max_workers: number of threads
    """
    print("Starting LLM calls...")
    max_workers = 4
    jsonstack = all_info

    def chunker(iterable, size):
        for i in range(0, len(iterable), size):
            yield iterable[i : i + size]

    batches = list(chunker(jsonstack, batch_size))
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(llm_brief, batch) for batch in batches]

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Batch failed: {e}")

    return results


def pop_dict_key(obj, key_to_remove):
    if isinstance(obj, dict):
        # Create a new dict to avoid modifying while iterating
        return {
            k: pop_dict_key(v, key_to_remove)
            for k, v in obj.items()
            if k != key_to_remove
        }
    elif isinstance(obj, list):
        return [pop_dict_key(item, key_to_remove) for item in obj]
    else:
        return obj


def llm_brief(jsonobj):
    """
    Strip raw payload bytes (to keep the prompt short) and send a batch of packet
    metadata to the LLM for summarisation.  Appends the response to summaries.
    """
    final = pop_dict_key(jsonobj, "Raw data")
    packet_infos = json.dumps(final)
    res = ollama.generate(
        model=llm_model,
        prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
        + packet_infos,
    )
    if res and "response" in res:
        with summaries_lock:
            summaries.append(res["response"])
        return res["response"]


def start_threading():
    """
    Process all TCP packets from the pre-loaded `packets` list using a ThreadPoolExecutor.

    Rather than re-reading the pcap file in every thread (which was the old behaviour),
    this submits one lightweight task per packet index.  ThreadPoolExecutor handles
    work-stealing, so threads stay busy even if individual packets take different amounts
    of time (e.g. when active-recon network calls vary in latency).
    """
    if __name__ == "__main__":
        print(
            f"Spooling up {nthreads} worker threads to process {totalp} packets...",
            file=sys.stderr,
        )
        # Build the list of packet indices that belong to TCP packets
        tcp_indices = [i for i, p in enumerate(packets) if p.haslayer("TCP")]

        with ThreadPoolExecutor(max_workers=nthreads) as executor:
            futures = {
                executor.submit(
                    process_packet_at_index,
                    idx,
                    args.source_port,
                    args.dest_port,
                    args.timeout,
                ): idx
                for idx in tcp_indices
            }
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
                try:
                    future.result()
                except Exception as exc:
                    if verbose >= 1:
                        print(
                            f"Packet {futures[future]} raised an exception: {exc}",
                            file=sys.stderr,
                        )


parser = argparse.ArgumentParser(
    prog="snitch.py",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(
        f"""                                
PacketSnitch.
This software analyzes pcap network captures. It extracts mostly TCP packet data,
writes testcases, and gathers extra information such as MIME types, entropy, geoip,
network class, banners, and more. Optionally, it performs active reconnaissance
to enrich the output with additional network and server information.  A full capture
summary is generated using a large languuage model to provide insights into the data.
        Outputs:
          - Testcase files: output_dir/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: output_dir/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for the entire
            capture.
                                 """,
    ),
    epilog="Example usage: \n   python3 snitch.py traffic.pcap -o output_dir -s 80 -d 8080 -T 5 -a",
)  # ignore fstring
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
    help="Only generate from this source port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate for this destination port.",
    type=int,
)
parser.add_argument(
    "-T",
    "--timeout",
    help="Timeout for network requests in seconds (default: 3).",
    type=int,
    default=3,
)
parser.add_argument(
    "-a",
    "--active-recon",
    help="Perform active reconnaissance to gather extra info (geoip, banners, titles).",
    action="store_true",
)
parser.add_argument(
    "-c",
    "--conf",
    help="Path to configuration YAML file (default: conf.yaml).",
)
parser.add_argument(
    "-v",
    "--verbose",
    help="Enable verbose output for debugging.",
    action="count",
    default=0,
)
parser.add_argument(
    "--nollm",
    help="Disable LLM summarisation regardless of configuration.",
    action="store_true",
)
verbose = parser.parse_args().verbose
args = parser.parse_args()  # parse once; verbose is needed by functions defined above
try:
    config = config_loader(args.conf if args.conf else "conf.yaml")
    # this next exception handles if ther is no config file
    # these are default opts that should work decently
except Exception:
    config = {
        "active_recon": True,
        "ollama": {
            "use_llm": True,
            "llm_brief": True,
            "model": "minimax-m2.5:cloud",
            "response_length": 340,
            "server_call_threads": 5,
            "batch_size": 4,
        },
        "threads": 16,
        "final_summary": True,
    }
pcap_path = args.pcap_file
geodat_path = script_dir + "common/GeoLite2-City.mmdb"
mac_vendors_path = script_dir + "common/mac-vendors-export.csv"
icann_csv_path = script_dir + "common/service-names-port-numbers.csv"

# --- Open the GeoIP database once for the lifetime of the process.
# The geoip2 Reader is documented as thread-safe for concurrent city() calls.
if os.path.exists(geodat_path):
    geoip_reader = geoip2.database.Reader(geodat_path)
else:
    print("Warning: GeoIP database not found at " + geodat_path, file=sys.stderr)

# --- Load ICANN port-description CSV into a dict for O(1) per-packet lookups.
# Without this, every call to get_port_description() would scan the full CSV.
if os.path.exists(icann_csv_path):
    with open(icann_csv_path, newline="", encoding="utf-8") as _f:
        for _row in csv.DictReader(_f):
            try:
                _port = int(_row.get("Port Number", ""))
                _proto = _row.get("Transport Protocol", "").strip().lower()
                _desc = _row.get("Description", "No description available")
                if _port and _proto:
                    port_desc_map[(_port, _proto)] = _desc
            except (ValueError, TypeError):
                pass
else:
    print("Warning: ICANN port CSV not found at " + icann_csv_path, file=sys.stderr)

# --- Load MAC vendor CSV into a dict for O(1) per-packet lookups.
# Without this, every call to mac_addr_to_vendor() would scan the full CSV.
if os.path.exists(mac_vendors_path):
    with open(mac_vendors_path, newline="", encoding="utf-8") as _f:
        for _row in csv.DictReader(_f):
            if "Mac Prefix" in _row and "Vendor Name" in _row:
                mac_vendor_map[_row["Mac Prefix"].upper()] = _row["Vendor Name"]
else:
    print("Warning: MAC vendor CSV not found at " + mac_vendors_path, file=sys.stderr)

totalp = 0
packets = scapy.rdpcap(args.pcap_file)  # type: ignore
total_packets = len(packets)
bs = 0
totalp = len([p for p in packets if p.haslayer("TCP")])
if totalp == 0:
    print("No packets found matching the specified port filters.", file=sys.stderr)
    sys.exit(1)
if "threads" in config and config["threads"]:
    nthreads = config["threads"]
outd = cur_dir + "/" + "testcases"
if args.output and args.output != "testcases":
    outd = args.output
    print("Using output directory: " + args.output, file=sys.stderr)
if "output_dir" in config:
    outd = cur_dir + "/" + config["output_dir"]
    print("Using output directory from config: " + outd, file=sys.stderr)
if not args.active_recon:
    if config["active_recon"]:
        ar = config["active_recon"]
    else:
        ar = False
if "ollama" in config and config["ollama"].get("model"):
    if config["ollama"].get("use_llm", False) and verbose >= 1:
        print(
            "LLM integration enabled. Using model: " + config["ollama"]["model"] + ".",
            file=sys.stderr,
        )
        llm_model = config["ollama"]["model"]
        if config["ollama"]["llm_brief"]:
            print(
                "LLM brief generation enabled. Only packet metadata will be sent through the LLM.",
                file=sys.stderr,
            )
        else:
            print(
                "LLM brief generation disabled. LLM will be used for full data packets!  This will take significantly more time, but will provide more detailed summaries for each packet.",
                file=sys.stderr,
            )
    response_length = config["ollama"].get("response_length", 200)
    bs = config["ollama"].get("batch_size", 5)
    use_llm = config["ollama"].get("use_llm", False)
if args.nollm:
    use_llm = False
    config = {
        "active_recon": True,
        "ollama": {
            "use_llm": False,
            "llm_brief": False,
        },
        "threads": 16,
        "final_summary": False,
    }


if llm_model and use_llm:
    if llm_model.endswith(":cloud"):
        if verbose >= 2:
            print(
                "Using cloud-based LLM model: "
                + "minimax-m2.5:cloud"  # doesn't need to be that fast, but has to look decent
                + ". Ensure you have network connectivity and API access.",
                file=sys.stderr,
            )
print(
    "Preparing to process "
    + str(totalp)
    + " packets with "
    + str(nthreads)
    + " threads.",
    file=sys.stderr,
)
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(outd):
    try:
        os.mkdir(outd)
        final_s = start_threading()
        # by_host(outd, final_s)
    except Exception:
        final_s = start_threading()
        # by_host(outd, final_s)
else:
    if (
        input(
            "Output directory already exists. Do you want to continue and potentially overwrite files? (y/n): "
        ).lower()
        != "y"
    ):
        print("Exiting to prevent overwriting files.", file=sys.stderr)
        sys.exit(1)
try:
    if os.path.isdir(outd):
        shutil.rmtree(outd, ignore_errors=True)
    # Small delay to ensure file system has completed deletions
    time.sleep(1)
    try:
        os.mkdir(outd)
        final_s = start_threading()
    except Exception:
        final_s = start_threading()
finally:
    final_summary = ""
    if config["ollama"]["llm_brief"] != True and use_llm:
        info_distiller(bs)
    else:
        # Strip raw payload bytes before sending to the LLM to keep the prompt small,
        # then restore the full all_info for the hosts.json output.
        all_info_orig = all_info.copy()
        all_info_new = pop_dict_key(all_info, "Raw data")
        all_info = all_info_new
        if all_info and use_llm:
            print("Generating LLM brief for batch of packets...")
            info_distiller(50)
        all_info = all_info_orig

    if config.get("final_summary", True) and config["ollama"].get("use_llm", True):
        drilldown = " ".join(summaries) if summaries else "No LLM summaries generated."
        try:
            final_res = ollama.generate(
                model=llm_model,
                prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
                + drilldown,
            )
            final_summary = final_res["response"]
            with open(outd + "/final_summary.txt", "w", encoding="utf-8") as _sf:
                _sf.write(final_summary)
            print("\n" + final_summary)
            print("\nFinal summary saved to: " + outd + "/final_summary.txt")
        except Exception as e:
            print("\nLLM Final summary generation error: " + str(e))

    # Always write hosts.json so the frontend can load data regardless of
    # whether LLM summarisation was enabled or succeeded.
    by_host(outd, final_summary)

    # Close the GeoIP reader now that all packets have been processed
    if geoip_reader is not None:
        geoip_reader.close()

    print(
        "Processing complete. Generated testcases and info files are located in: "
        + outd,
        file=sys.stderr,
    )

    sys.exit(0)
