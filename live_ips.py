from scapy.all import sniff
import time
import joblib
import pandas as pd
import subprocess
import time
import warnings
warnings.filterwarnings("ignore")

model = joblib.load("model/multi_attack_model.pkl")

WINDOW = 5

blocked_ips = {}
BLOCK_DURATION = 60  # temporary block time

packet_count = 0
byte_count = 0
syn_count = 0
ack_count = 0
udp_count = 0
icmp_count = 0
packet_sizes = []
src_ip_counts = {}

start_time = time.time()

#blocked_ips = set()

def process_packet(packet):
    global packet_count, byte_count
    global syn_count, ack_count, udp_count, icmp_count
    global packet_sizes, src_ip_counts, start_time

    packet_count += 1
    byte_count += len(packet)
    packet_sizes.append(len(packet))

    if packet.haslayer("IP"):
        src = packet["IP"].src
        src_ip_counts[src] = src_ip_counts.get(src, 0) + 1

    if packet.haslayer("TCP"):
        flags = packet["TCP"].flags
        if flags == "S":
            syn_count += 1
        if flags == "A":
            ack_count += 1

    if packet.haslayer("UDP"):
        udp_count += 1

    if packet.haslayer("ICMP"):
        icmp_count += 1

    if time.time() - start_time >= WINDOW:
        analyze_window()

def analyze_window():
    global packet_count, byte_count
    global syn_count, ack_count, udp_count, icmp_count
    global packet_sizes, src_ip_counts, start_time
    global blocked_ips
    
    unblock_expired_ips()

    if packet_count == 0:
        reset()
        return

    packets_per_sec = packet_count / WINDOW
    bytes_per_sec = byte_count / WINDOW
    avg_packet_size = sum(packet_sizes) / len(packet_sizes)
    unique_src_ips = len(src_ip_counts)

    data = pd.DataFrame([[
        packets_per_sec,
        bytes_per_sec,
        syn_count,
        ack_count,
        udp_count,
        icmp_count,
        unique_src_ips,
        avg_packet_size
    ]], columns=[
        "packets_per_sec",
        "bytes_per_sec",
        "syn_count",
        "ack_count",
        "udp_count",
        "icmp_count",
        "unique_src_ips",
        "avg_packet_size"
    ])

    prediction = model.predict(data)[0]

    if prediction == 0:
        print("Traffic: NORMAL")
    else:
        attack_types = {1: "SYN_FLOOD", 2: "UDP_FLOOD", 3: "ICMP_FLOOD"}
        print(f"Attack Detected: {attack_types[prediction]}")

        # Identify top source IP
        attacker_ip = max(src_ip_counts, key=src_ip_counts.get)

        if attacker_ip not in blocked_ips:
    	    block_ip(attacker_ip)

    reset()

#def block_ip(ip):
#    print(f"Blocking IP: {ip}")
#    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    
def block_ip(ip):
    global blocked_ips
    print(f"Blocking IP: {ip} for {BLOCK_DURATION} seconds")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips[ip] = time.time()
    
def unblock_expired_ips():
    global blocked_ips

    current_time = time.time()
    expired_ips = []

    for ip, block_time in blocked_ips.items():
        if current_time - block_time >= BLOCK_DURATION:
            print(f"Unblocking IP: {ip}")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            expired_ips.append(ip)

    for ip in expired_ips:
        del blocked_ips[ip]

def reset():
    global packet_count, byte_count
    global syn_count, ack_count, udp_count, icmp_count
    global packet_sizes, src_ip_counts, start_time

    packet_count = 0
    byte_count = 0
    syn_count = 0
    ack_count = 0
    udp_count = 0
    icmp_count = 0
    packet_sizes = []
    src_ip_counts = {}
    start_time = time.time()

sniff(iface="enp0s3", prn=process_packet)
