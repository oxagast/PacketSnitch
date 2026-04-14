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

stopEvent = threading.Event()

try:
    import scapy.all as scapy
except ImportError:
    import scapy

activeRecon = "False"
numWorkerThreads = 6
numLlmThreads = 5
llmResponseLength = 100
llmModelName = "minimax-m2.5:cloud"
useLlm = False

# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
llmSummaries = []
llmSummariesLock = threading.Lock()
allPacketInfo = []
allPacketInfoLock = threading.Lock()

# Concurrency controls
llmCallLock = threading.Semaphore(numLlmThreads)  # cap simultaneous LLM calls

hostOutputFile = "hosts.json"
currentDir = os.getcwd()
scriptDir = os.path.dirname(os.path.realpath(__file__)) + "/"

# --- Lookup tables loaded once at startup (see init_lookup_tables()) ---
# Keyed (port_int, "tcp"/"udp") -> description string
portDescriptionMap: dict = {}
# Keyed by uppercase MAC macPrefix (e.g. "00:1A:2B") -> vendor name
macVendorMap: dict = {}

# --- GeoIP reader opened once and reused across all packets ---
# Protected by geoIpCacheLock for the cache; the Reader itself is thread-safe.
geoIpReader = None
geoIpCache: dict = {}
geoIpCacheLock = threading.Lock()

# --- Banner cache: (ip, port) -> banner dict, avoids redundant socket probes ---
cachedBanners: dict = {}
cachedBannersLock = threading.Lock()


def llm_query(packetInfoStr):
    """
    Query a large language model (LLM) with packet information for summarization.
    Handles retries and concurrency limits. Appends responses to the global llmSummaries list.
    """
    with llmCallLock:
        try:
            if ollama and useLlm and packetInfoStr:
                # Attempt up to 2 times with exponential backoff; halve the payload on each retry
                for retryCount in range(2):
                    try:
                        llmResponse = ollama.generate(
                            model=llmModelName,
                            prompt=f"Tell me what you can about the following network capture (encoded in json, from pcap), its payload, and any interesting or unusual traits... respond with a single paragraph around {llmResponseLength} words: {packetInfoStr}",
                        )
                        if llmResponse and "response" in llmResponse:
                            # Protect list append from concurrent thread writes
                            with llmSummariesLock:
                                llmSummaries.append(llmResponse["response"])
                        else:
                            return {"Summary": ""}
                    except ResponseError as responseErr:
                        if verbose >= 2:
                            print(
                                f"LLM API response error (attempt {retryCount + 1}/3): {str(responseErr)}",
                                file=sys.stderr,
                            )
                        time.sleep(2**retryCount)  # Exponential backoff
                        packetInfoStr = packetInfoStr[
                            : int(len(packetInfoStr) / (2**retryCount))
                        ]
                        if verbose >= 1:
                            print(
                                f"Retrying with truncated (halved) string (attempt {retryCount + 1}/3)...",
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
    Uses the portDescriptionMap dict loaded once at startup for O(1) lookup.
    """
    return portDescriptionMap.get((port, protocol), "No description available")


def reverse_dns_lookup(ip):
    """
    Perform a reverse DNS lookup for the given IP address.
    Returns a dictionary with resolution status and hostnames or error.
    """

    try:
        dnsResult = socket.gethostbyaddr(ip)
        return (
            {"Resolved": True, "Hostnames": dnsResult}
            if dnsResult and len(dnsResult) > 0
            else {"Resolved": False, "Error": "No PTR record found"}
        )
    except Exception as e:
        return {
            "Resolved": False,
            "Error": "Address resolution error: " + str(e),
        }


def get_serv_banner(ip, port, timeout, hostname):
    """
    Retrieve the service banner, SSL certificate, and page title for a given IP and port.
    Uses a dict cache keyed by (ip, port) to avoid redundant network probes.
    Handles both HTTP and HTTPS. Returns a dict with banner, page title, and encryption data.
    """

    ipPortKey = (ip, port)
    # Fast O(1) cache hit check before doing any network work
    with cachedBannersLock:
        if ipPortKey in cachedBanners:
            return cachedBanners[ipPortKey]

    sslCert = "Unavailable"
    cipherInfo = "N/A"
    sslVersion = "N/A"
    pageTitle = "N/A"
    bannerInfo = {}
    # Get page title for HTTP/HTTPS ports
    try:
        if port == 443:
            pageTitle = get_page_title("https://" + hostname + ":" + str(port), timeout)
        else:
            pageTitle = get_page_title("http://" + hostname + ":" + str(port), timeout)
    except Exception:
        pageTitle = "N/A"
    # Try to fetch SSL certificate info (ignore errors; port may not support TLS)
    try:
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.settimeout(timeout)
        sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sslContext.check_hostname = False
        sslContext.verify_mode = ssl.CERT_NONE
        sslSocket = sslContext.wrap_socket(tcpSocket, server_hostname=ip)
        sslSocket.connect((ip, port))
        if sslSocket:
            sslCert = sslSocket.getpeercert()
            cipherInfo = sslSocket.cipher()
            sslVersion = sslSocket.version()
        tcpSocket.close()
    except Exception:
        pass
    # Try to fetch banner from server
    try:
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.settimeout(timeout)
        tcpSocket.connect((ip, port))
        banner = tcpSocket.recv(1024).decode(errors="ignore").strip()
        if len(banner) > 0:
            bannerInfo = {
                "Banner": banner,
                "Page Title": pageTitle,
                "Encryption Data": {
                    "SSL Cert": sslCert,
                    "SSL Version": sslVersion,
                    "Encrypted With": cipherInfo,
                }
                if sslVersion != "N/A"
                else "N/A",
            }
            tcpSocket.close()
        else:
            # No passive banner; try an HTTP HEAD request as a fallback
            tcpSocket.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = tcpSocket.recv(1024).decode(errors="ignore").strip()
            tcpSocket.close()
            if len(banner) > 0:
                bannerInfo = {
                    "Banner": banner,
                    "Page Title": pageTitle,
                    "Encryption Data": {
                        "SSL Cert": sslCert,
                        "SSL Version": sslVersion,
                        "Encrypted With": cipherInfo,
                    }
                    if sslVersion != "N/A"
                    else "N/A",
                }
            else:
                bannerInfo = {
                    "Page Title": pageTitle,
                    "Encryption Data": {
                        "SSL Cert": sslCert,
                        "SSL Version": sslVersion,
                        "Encrypted With": cipherInfo,
                    }
                    if sslVersion != "N/A"
                    else "N/A",
                }
    except Exception:
        bannerInfo = {
            "Page Title": pageTitle,
            "Encryption Data": {
                "SSL Cert": sslCert,
                "SSL Version": sslVersion,
                "Encrypted With": cipherInfo,
            }
            if sslVersion != "N/A"
            else "N/A",
        }
    # Store in cache so repeated calls for the same (ip, port) are free
    with cachedBannersLock:
        cachedBanners[ipPortKey] = bannerInfo
    return bannerInfo


def get_page_title(url, timeout):
    """
    Fetch the HTML page title from the given URL with a timeout.
    Returns the title string or "N/A" if unavailable.
    """

    try:
        requests.packages.urllib3.disable_warnings(  # ignore
            category=InsecureRequestWarning  # ignore request warning
        )  # ignore
        httpResponse = requests.get(url, timeout=timeout, verify=False)
        httpResponse.raise_for_status()
        responseContent = httpResponse.content
        htmlParser = BeautifulSoup(responseContent, "html.parser")
        return htmlParser.title.string if htmlParser.title else "N/A"
    except Exception:
        return "N/A"


def write_testcase(data, outputDirPath, portDir, index):
    """
    Write raw packet payload bytes to a testcase file.
    Creates the per-port sub-directory on first use; errors there are non-fatal.
    Uses a context manager so the file descriptor is always released.
    """
    destDir = outputDirPath + "/" + portDir
    if not os.path.exists(destDir):
        try:
            os.mkdir(destDir)
        except Exception:
            print("Error: Nonfatal: Could not create minor dir.")
    with open(destDir + "/pcap.data_packet." + str(index) + ".dat", "wb") as out:
        out.write(data)


def join_info(outputDirPath, portDir, index, dataTypeJson, packetInfoJson, host):
    """
    Merge packet-level info with extra analysis info and write as a JSON file.
    Thread-safe: uses allPacketInfoLock when appending to the shared allPacketInfo list.
    """
    mergedJson = {
        "Packet Info": json.loads(packetInfoJson),
        "Extra Info": json.loads(dataTypeJson),
    }
    path = outputDirPath + "/" + portDir + "/pcap.info_packet." + str(index) + ".json"
    with open(path, "wb+") as out:
        out.write(json.dumps(mergedJson).encode())
    if verbose >= 2:
        print(json.dumps(mergedJson, indent=2))
    # Protect the shared list from concurrent thread writes
    with allPacketInfoLock:
        allPacketInfo.append({"Host": host, "Packet": mergedJson})
    return mergedJson


packetsByHost = {}


def sort_and_index_packets(hostPacketMap):
    for host, packets in hostPacketMap.items():
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

    return hostPacketMap


def by_host(outputDirPath, finalSummary):
    """
    Organise allPacketInfo entries by destination host and write the result to hosts.json.
    Bug fix: the original code created the empty list but then only appended on the
    *else* branch, silently dropping the first packet for every unique host.
    Now every packet is always appended.
    """
    global packetsByHost
    for entry in allPacketInfo:
        host = entry.get("Host")
        if host not in packetsByHost:
            packetsByHost[host] = []
        # Always append — previously the first packet per host was lost
        packetsByHost[host].append(entry.get("Packet"))

    packetsByHost = sort_and_index_packets(packetsByHost)

    # Write the consolidated hosts file; use a context manager to guarantee flush/close
    with open(outputDirPath + "/" + hostOutputFile, "w+", encoding="utf-8") as f:
        f.write(
            json.dumps({"Host": packetsByHost, "Final Summary": finalSummary}, indent=2)
        )


def get_netclass(ip):
    """
    Determine the network class (A, B, C, or Unknown) of an IPv4 address.
    """
    ipAddressObj = ipaddress.ip_address(ip)
    # Get the first octet
    firstOctet = int(str(ipAddressObj).split(".")[0])
    # Determine the class
    if 1 <= firstOctet <= 127:
        return "A"
    elif 128 <= firstOctet <= 191:
        return "B"
    elif 192 <= firstOctet <= 223:
        return "C"
    elif 224 <= firstOctet <= 239:
        return "D"
    elif 240 <= firstOctet <= 255:
        return "E"
    else:
        return "Invalid IP"


def safe_decompress(compressedData):
    """
    Safely decompress gzip or zlib-compressed data.
    Returns the decompressed bytes, or empty bytes on error.
    """

    # Initialize decompressor
    # Handle gzip and zlib formats
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    result = b""
    try:
        result = decompressor.decompress(compressedData)
        result += decompressor.flush()
    except zlib.error:
        pass
    return result


def get_geoip_info(ip, srcOrDst):
    """
    Look up GeoIP information (country, city, postal code, timezone) for an IP address.
    Uses geoIpReader opened once at startup and a per-session cache dict so that
    repeated lookups for the same IP cost nothing beyond a dict read.
    Returns a dictionary with location data or error message.
    """
    if geoIpReader is None:
        return {"Location": "Error: GeoIP database not found!"}

    # Check cache first (lock only for the brief check/insert, not for the DB query)
    geoIpCacheKey = (ip, srcOrDst)
    with geoIpCacheLock:
        if geoIpCacheKey in geoIpCache:
            return geoIpCache[geoIpCacheKey]

    try:
        geoIpResponse = geoIpReader.city(ip)
        if srcOrDst == "src":
            geoIpResult = {
                "Country": geoIpResponse.country.name,
                "loc.src.country": geoIpResponse.country.name,
                "City": geoIpResponse.city.name,
                "loc.src.city": geoIpResponse.city.name,
                "Postal Code": geoIpResponse.postal.code,  # type: ignore
                "loc.src.postal": geoIpResponse.postal.code,  # type: ignore
                "Time Zone": geoIpResponse.location.time_zone,  # type: ignore
                "loc.src.tz": geoIpResponse.location.time_zone,  # type: ignore
                "loc.src.timezone": geoIpResponse.location.time_zone,  # type: ignore
            }
        else:  # srcOrDst == "dst"
            geoIpResult = {
                "Country": geoIpResponse.country.name,
                "loc.dst.country": geoIpResponse.country.name,
                "City": geoIpResponse.city.name,
                "loc.dst.city": geoIpResponse.city.name,
                "Postal Code": geoIpResponse.postal.code,  # type: ignore
                "loc.dst.postal": geoIpResponse.postal.code,  # type: ignore
                "Time Zone": geoIpResponse.location.time_zone,  # type: ignore
                "loc.dst.tz": geoIpResponse.location.time_zone,  # type: ignore
                "loc.dst.timezone": geoIpResponse.location.time_zone,  # type: ignore
            }
    except geoip2.errors.AddressNotFoundError:  # type: ignore
        geoIpResult = {"Location": "Localnet"}
    except Exception as e:
        geoIpResult = {"Location": "Error: " + str(e)}

    # Store in cache so subsequent calls for this IP are instant
    with geoIpCacheLock:
        geoIpCache[geoIpCacheKey] = geoIpResult
    return geoIpResult


def get_datatypes(data, dstPort, sourceIp, destIp, timeout):
    """
    Analyze data to determine MIME type, decompress if possible, and extract traits.
    Returns a dictionary with MIME type, decompression info, data types, and traits.
    """
    mimeType = magic.from_buffer(data, mime=True)
    lineDescs = []
    decompData = ""
    decomprInfo = {"Decompressed": False}
    for ln in data.splitlines():
        lineDescs.append(magic.from_buffer(ln))
        decompData = safe_decompress(ln)
        if decompData and len(decompData) > 0:
            decomprInfo = {
                "Decompressed data": {
                    "Decompressed Hex Encoded": decompData.hex(),
                    "payload.decompressed.hex": decompData.hex(),
                    "Decompressed ASCII Encoded": decompData.decode(errors="ignore"),
                    "payload.decompressed.ascii": decompData.decode(errors="ignore"),
                },
            }
    uniqueDescs = list(set(lineDescs))
    if "empty" in uniqueDescs:
        uniqueDescs.remove("empty")
    if "data" in uniqueDescs:
        uniqueDescs.remove("data")
    if uniqueDescs == []:
        uniqueDescs = ["Unknown data type"]
    traitData = get_traits(data, dstPort, sourceIp, destIp, timeout)
    dataTypeResult = {
        "MIME Type": mimeType,
        "payload.mime": mimeType,
        "Decompressed": decomprInfo,
        "payload.decompressed": decomprInfo,
        "Data Types": uniqueDescs,
        "Traits": traitData,
    }
    return dataTypeResult


def get_serv(port, protocol="tcp"):
    """
    Return the service name for a given port and protocol using the system's services database.
    """

    try:
        serviceName = socket.getservbyport(port, protocol)
        return serviceName
    except Exception:
        return "Unknown"


def get_traits(data, dstPort, sourceIp, destIp, timeout):
    """
    Analyze data for entropy, charsetType, encoding, and network/server traits.
    Returns a dictionary with entropy, network data, length, server info, and character info.
    """

    byteCounts = np.bincount(list(data))
    shannonEntropy = entropy(byteCounts, base=2)
    dataLength = len(data)
    protoName = get_serv(dstPort)
    charsetType = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    uniqueCharCount = len(set(data))
    uniqueCharsSet = set(data)
    if activeRecon:
        dnsHostnames = reverse_dns_lookup(destIp)
    else:
        dnsHostnames = {
            "Resolved": False,
            "Error": "Active recon not performed",
            "Hostnames": [],
        }
    if activeRecon and dnsHostnames.get("Hostnames") is not None:
        banner = get_serv_banner(
            destIp,
            dstPort,
            timeout,
            dnsHostnames.get("Hostnames")[0]
            if dnsHostnames.get("Resolved")
            else destIp,  # ignore subscript warning, it checks for resolution first
        )
    else:
        banner = "Active recon not performed"
    encoding = chardet.detect(data)
    srcGeoInfo = get_geoip_info(sourceIp, "src")
    dstGeoInfo = get_geoip_info(destIp, "dst")
    srcNetClass = get_netclass(sourceIp)
    dstNetClass = get_netclass(destIp)
    portDesc = get_port_description(dstPort)
    return {
        "Shannon Entropy": shannonEntropy,
        "payload.entropy": shannonEntropy,
        "Network Data": {
            "Source IP": {
                "Class": srcNetClass,
                "ip.src.class": srcNetClass,
                "Location": srcGeoInfo,
                "ip.src.location": srcGeoInfo,
            },
            "Destination IP": {
                "Class": dstNetClass,
                "ip.dst.class": dstNetClass,
                "Location": dstGeoInfo,
                "ip.dst.location": dstGeoInfo,
            },
            "Port Protcol": protoName,
            "tcp.proto": protoName,
            "Port Description": portDesc,
            "tcp.desc": portDesc,
            "Hostnames": dnsHostnames,
            "dns.hostnames": dnsHostnames,
        },
        "Length": dataLength,
        "Server Info": banner,
        "host.banner": banner,
        "Characters": {
            "Charset": charsetType,
            "payload.charset": charsetType,
            "Encoding": encoding
            if shannonEntropy <= 4.85
            else "Unavailable for high entropy data",
            "payload.encoding": encoding
            if shannonEntropy <= 4.85
            else "Unavailable for high entropy data",
            "Characters used": uniqueCharCount,
            "payload.chars.used": uniqueCharCount,
            "Unique characters": bytearray(list(uniqueCharsSet)).hex(),
        },
    }


def mac_addr_to_vendor(macAddr):
    """
    Return the vendor name for a MAC address.
    Uses macVendorMap dict loaded once at startup for O(1) macPrefix lookup.
    MAC prefixes are stored as the first 8 characters of the normalised address (e.g. "00:1A:2B").
    """
    macPrefix = macAddr[:8].upper()
    return macVendorMap.get(macPrefix, "Unknown Vendor")


def packet_loop(p, packetIndex, srcPortFilter, dstPortFilter, timeout):
    """
    Process a single scapy packet: extract TCP payload, write the raw testcase file,
    gather analysis data (MIME, entropy, geoip, etc.) and merge everything into a
    single JSON output file.

    packetIndex is the 0-based position of this packet in the full capture, used as
    the filename index so files from concurrent threads do not collide.
    Returns the merged info dict, or None if the packet should be skipped.
    """
    srcMacAddr = p.src if p.haslayer("Ethernet") else "N/A"
    dstMacAddr = p.dst if p.haslayer("Ethernet") else "N/A"
    srcMacVendor = (
        mac_addr_to_vendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    )
    dstMacVendor = (
        mac_addr_to_vendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"
    )
    if not p.haslayer("IP"):
        return None
    if not p.haslayer("TCP"):
        return None

    rawPayload = p["TCP"].payload.original
    srcPort = p["TCP"].sport
    dstPort = p["TCP"].dport
    dstPortStr = str(dstPort)
    if (srcPortFilter is None or srcPort == srcPortFilter) and (dstPortFilter is None or dstPort == dstPortFilter):
        if rawPayload is not None and len(rawPayload) > 0:
            write_testcase(rawPayload, outputDir, dstPortStr, packetIndex)
            dataTypeInfo = get_datatypes(rawPayload, dstPort, p["IP"].src, p["IP"].dst, timeout)
            timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            # Build TCP flag string once
            tcpFlags = ""
            if p["TCP"].flags.S:
                tcpFlags += "SYN|"
            if p["TCP"].flags.A:
                tcpFlags += "ACK|"
            if p["TCP"].flags.F:
                tcpFlags += "FIN|"
            if p["TCP"].flags.R:
                tcpFlags += "RST|"
            if p["TCP"].flags.P:
                tcpFlags += "PSH|"
            if p["TCP"].flags.U:
                tcpFlags += "URG|"
            if p["TCP"].flags.ECE:
                tcpFlags += "ECE|"
            if p["TCP"].flags.CWR:
                tcpFlags += "CWR|"
            if tcpFlags.endswith("|"):
                tcpFlags = tcpFlags[:-1]

            # Resolve geoip once per packet so we don't hit the cache (or DB) twice
            # for the same IP within a single packet.
            srcGeoInfo = get_geoip_info(p["IP"].src, "src")
            dstGeoInfo = get_geoip_info(p["IP"].dst, "dst")
            isLocalNetwork = (
                srcGeoInfo.get("Location") == "Localnet"
                and dstGeoInfo.get("Location") == "Localnet"
            )

            packetInfo = {
                "Packet Processed": int(packetIndex),
                "Packet Timestamp": timestamp,
                "packet.timestamp": timestamp,
                # Only include Ethernet MAC data for LAN-local traffic
                "Ethernet Frame": {
                    "MAC Source": srcMacAddr,
                    "ether.src.mac.addr": srcMacAddr,
                    "MAC Destination": dstMacAddr,
                    "ether.dst.mac.addr": dstMacAddr,
                    "MAC Source Vendor": srcMacVendor,
                    "ether.src.mac.vendor": srcMacVendor,
                    "MAC Destination Vendor": dstMacVendor,
                    "ether.dst.mac.vendor": dstMacVendor,
                }
                if isLocalNetwork
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
                    "Source port": int(srcPort),
                    "tcp.src.port": int(srcPort),
                    "Destination port": int(dstPort),
                    "tcp.dst.port": int(dstPort),
                    "TCP checksum": hex(int(p["TCP"].chksum)),
                    "tcp.chksum": hex(int(p["TCP"].chksum)),
                    "Urgent flag": bool(p["TCP"].urgptr),
                    "tcp.urgptr": bool(p["TCP"].urgptr),
                    "TCP Flag Data": {
                        "Flags": tcpFlags if tcpFlags else "None",
                        "tcp.flags": tcpFlags if tcpFlags else "None",
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
                        "Hex Encoded": rawPayload.hex(),
                        "payload.hex": rawPayload.hex(),
                        "ASCII Encoded": rawPayload.decode(errors="ignore"),
                        "payload.ascii": rawPayload.decode(errors="ignore"),
                    },
                    "Packet": bytes(p).hex(),
                    "packet.hex": bytes(p).hex(),
                    "Payload Length": len(rawPayload),
                    "payload.len": len(rawPayload),
                },
            }
            # Use the non-local IP as the host key; fall back to src for LAN captures
            hostKey = (
                p["IP"].dst if dstGeoInfo.get("Location") != "Localnet" else p["IP"].src
            )
            mergedInfo = join_info(
                outputDir,
                dstPortStr,
                packetIndex,
                json.dumps(dataTypeInfo).encode(),
                json.dumps(packetInfo).encode(),
                hostKey,
            )
            return mergedInfo


def process_packet_at_index(packetIndex, srcPortFilter, dstPortFilter, timeout):
    """
    Thin wrapper used by ThreadPoolExecutor.map so we can pass a single (index, packet)
    task without pickling scapy packet objects.  The global `packets` list is already
    loaded in memory, so this is just a cheap indexed lookup + the real per-packet work.
    """
    if stopEvent.is_set():
        return None
    p = packets[packetIndex]
    return packet_loop(p, packetIndex, srcPortFilter, dstPortFilter, timeout)


llmSummariesBatch = []


def info_distiller(batchSize):
    """
    lines: iterable of input data
    worker_fn: function that takes a list (batch) and processes it
    batchSize: number of items per batch
    maxWorkers: number of threads
    """
    print("Starting LLM calls...")
    maxWorkers = 4
    jsonStack = allPacketInfo

    def chunker(iterable, size):
        for i in range(0, len(iterable), size):
            yield iterable[i : i + size]

    packetBatches = list(chunker(jsonStack, batchSize))
    results = []

    with ThreadPoolExecutor(max_workers=maxWorkers) as executor:
        taskFutures = [executor.submit(llm_brief, batch) for batch in packetBatches]

        for future in as_completed(taskFutures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Batch failed: {e}")

    return results


def pop_dict_key(obj, keyToRemove):
    if isinstance(obj, dict):
        # Create a new dict to avoid modifying while iterating
        return {
            k: pop_dict_key(v, keyToRemove)
            for k, v in obj.items()
            if k != keyToRemove
        }
    elif isinstance(obj, list):
        return [pop_dict_key(item, keyToRemove) for item in obj]
    else:
        return obj


def llm_brief(jsonBatch):
    """
    Strip raw payload bytes (to keep the prompt short) and send a batch of packet
    metadata to the LLM for summarisation.  Appends the response to llmSummaries.
    """
    strippedJson = pop_dict_key(jsonBatch, "Raw data")
    packetInfoStr = json.dumps(strippedJson)
    llmResponse = ollama.generate(
        model=llmModelName,
        prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
        + packetInfoStr,
    )
    if llmResponse and "response" in llmResponse:
        with llmSummariesLock:
            llmSummaries.append(llmResponse["response"])
        return llmResponse["response"]


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
            f"Spooling up {numWorkerThreads} worker threads to process {totalTcpPackets} packets...",
            file=sys.stderr,
        )
        # Build the list of packet indices that belong to TCP packets
        tcpPacketIndices = [i for i, p in enumerate(packets) if p.haslayer("TCP")]

        with ThreadPoolExecutor(max_workers=numWorkerThreads) as executor:
            taskFutures = {
                executor.submit(
                    process_packet_at_index,
                    idx,
                    args.source_port,
                    args.dest_port,
                    args.timeout,
                ): idx
                for idx in tcpPacketIndices
            }
            for future in as_completed(taskFutures):
                if stopEvent.is_set():
                    break
                try:
                    future.result()
                except Exception as exc:
                    if verbose >= 1:
                        print(
                            f"Packet {taskFutures[future]} raised an exception: {exc}",
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
summary is generated using a large language model to provide insights into the data.
        Outputs:
          - Testcase files: outputDirPath/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: outputDirPath/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for the entire
            capture.
                                 """,
    ),
    epilog="Example usage: \n   python3 snitch.py traffic.pcap -o outputDirPath -s 80 -d 8080 -T 5 -a",
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
            "batch_size": 65,
        },
        "threads": 16,
        "final_summary": True,
    }
pcapFilePath = args.pcap_file
geoDbPath = scriptDir + "common/GeoLite2-City.mmdb"
macVendorsPath = scriptDir + "common/mac-vendors-export.csv"
icannCsvPath = scriptDir + "common/service-names-port-numbers.csv"

# --- Open the GeoIP database once for the lifetime of the process.
# The geoip2 Reader is documented as thread-safe for concurrent city() calls.
if os.path.exists(geoDbPath):
    geoIpReader = geoip2.database.Reader(geoDbPath)
else:
    print("Warning: GeoIP database not found at " + geoDbPath, file=sys.stderr)

# --- Load ICANN port-description CSV into a dict for O(1) per-packet lookups.
# Without this, every call to get_port_description() would scan the full CSV.
if os.path.exists(icannCsvPath):
    with open(icannCsvPath, newline="", encoding="utf-8") as csvFile:
        for csvRow in csv.DictReader(csvFile):
            try:
                portNum = int(csvRow.get("Port Number", ""))
                protoStr = csvRow.get("Transport Protocol", "").strip().lower()
                portDescription = csvRow.get("Description", "No description available")
                if portNum and protoStr:
                    portDescriptionMap[(portNum, protoStr)] = portDescription
            except (ValueError, TypeError):
                pass
else:
    print("Warning: ICANN port CSV not found at " + icannCsvPath, file=sys.stderr)

# --- Load MAC vendor CSV into a dict for O(1) per-packet lookups.
# Without this, every call to mac_addr_to_vendor() would scan the full CSV.
if os.path.exists(macVendorsPath):
    with open(macVendorsPath, newline="", encoding="utf-8") as csvFile:
        for csvRow in csv.DictReader(csvFile):
            if "Mac Prefix" in csvRow and "Vendor Name" in csvRow:
                macVendorMap[csvRow["Mac Prefix"].upper()] = csvRow["Vendor Name"]
else:
    print("Warning: MAC vendor CSV not found at " + macVendorsPath, file=sys.stderr)

totalTcpPackets = 0
packets = scapy.rdpcap(args.pcap_file)  # type: ignore
allPacketCount = len(packets)
llmBatchSize = 0
totalTcpPackets = len([p for p in packets if p.haslayer("TCP")])
if totalTcpPackets == 0:
    print("No packets found matching the specified port filters.", file=sys.stderr)
    sys.exit(1)
if "threads" in config and config["threads"]:
    numWorkerThreads = config["threads"]
outputDir = currentDir + "/" + "testcases"
if args.output and args.output != "testcases":
    outputDir = args.output
    print("Using output directory: " + args.output, file=sys.stderr)
if "output_dir" in config:
    outputDir = currentDir + "/" + config["output_dir"]
    print("Using output directory from config: " + outputDir, file=sys.stderr)
if not args.active_recon:
    if config["active_recon"]:
        activeRecon = config["active_recon"]
    else:
        activeRecon = False
if "ollama" in config and config["ollama"].get("model"):
    if config["ollama"].get("use_llm", False) and verbose >= 1:
        print(
            "LLM integration enabled. Using model: " + config["ollama"]["model"] + ".",
            file=sys.stderr,
        )
        llmModelName = config["ollama"]["model"]
        if config["ollama"]["llm_brief"]:
            print(
                "LLM brief generation enabled. Only packet metadata will be sent through the LLM.",
                file=sys.stderr,
            )
        else:
            print(
                "LLM brief generation disabled. LLM will be used for full data packets!  This will take significantly more time, but will provide more detailed llmSummaries for each packet.",
                file=sys.stderr,
            )
    llmResponseLength = config["ollama"].get("response_length", 200)
    llmBatchSize = config["ollama"].get("batch_size", 65)
    useLlm = config["ollama"].get("use_llm", False)
if args.nollm:
    useLlm = False
    config = {
        "active_recon": True,
        "ollama": {
            "use_llm": False,
            "llm_brief": False,
        },
        "threads": 16,
        "final_summary": False,
    }


if llmModelName and useLlm:
    if llmModelName.endswith(":cloud"):
        if verbose >= 2:
            print(
                "Using cloud-based LLM model: "
                + "minimax-m2.5:cloud"  # doesn't need to be that fast, but has to look decent
                + ". Ensure you have network connectivity and API access.",
                file=sys.stderr,
            )
print(
    "Preparing to process "
    + str(totalTcpPackets)
    + " packets with "
    + str(numWorkerThreads)
    + " threads.",
    file=sys.stderr,
)
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
if not os.path.exists(outputDir):
    try:
        os.mkdir(outputDir)
        threadingResult = start_threading()
        # by_host(outputDir, threadingResult)
    except Exception:
        threadingResult = start_threading()
        # by_host(outputDir, threadingResult)
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
    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir, ignore_errors=True)
    # Small delay to ensure file system has completed deletions
    time.sleep(1)
    try:
        os.mkdir(outputDir)
        threadingResult = start_threading()
    except Exception:
        threadingResult = start_threading()
finally:
    finalSummary = ""
    if config["ollama"]["llm_brief"] != True and useLlm:
        info_distiller(llmBatchSize)
    else:
        # Strip raw payload bytes before sending to the LLM to keep the prompt small,
        # then restore the full allPacketInfo for the hosts.json output.
        allPacketInfoBackup = allPacketInfo.copy()
        strippedPacketInfo = pop_dict_key(allPacketInfo, "Raw data")
        allPacketInfo = strippedPacketInfo
        if allPacketInfo and useLlm:
            print("Generating LLM brief for batch of packets...")
            info_distiller(50)
        allPacketInfo = allPacketInfoBackup

    if config.get("final_summary", True) and config["ollama"].get("use_llm", True):
        joinedSummaries = " ".join(llmSummaries) if llmSummaries else "No LLM summaries generated."
        try:
            finalLlmResponse = ollama.generate(
                model=llmModelName,
                prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
                + joinedSummaries,
            )
            finalSummary = finalLlmResponse["response"]
            with open(outputDir + "/final_summary.txt", "w", encoding="utf-8") as summaryFile:
                summaryFile.write(finalSummary)
            print("\n" + finalSummary)
            print("\nFinal summary saved to: " + outputDir + "/final_summary.txt")
        except Exception as e:
            print("\nLLM Final summary generation error: " + str(e))

    # Always write hosts.json so the frontend can load data regardless of
    # whether LLM summarisation was enabled or succeeded.
    by_host(outputDir, finalSummary)

    # Close the GeoIP reader now that all packets have been processed
    if geoIpReader is not None:
        geoIpReader.close()

    print(
        "Processing complete. Generated testcases and info files are located in: "
        + outputDir,
        file=sys.stderr,
    )

    sys.exit(0)
