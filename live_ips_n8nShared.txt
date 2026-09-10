from scapy.all import sniff
from scapy.layers.inet import IP
import time
import joblib
import pandas as pd
import subprocess
import datetime
import requests
import warnings
warnings.filterwarnings("ignore")

my_ip = "192.168.151.3"

def send_to_n8n(data):
    try:
        requests.post("http://localhost:5678/webhook-test/ips-alert", json=data)
    except:
        pass

model = joblib.load("model/multi_attack_model.pkl")

WINDOW = 5

#blocked_ips = {}
#BLOCK_DURATION = 60  # temporary block time

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

    if packet.haslayer(IP):
        if packet[IP].dst == my_ip:
            src_ip = packet[IP].src
            # Ignore localhost and your own machine
            if src_ip != my_ip:
                src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1

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
   # global blocked_ips
    
    #unblock_expired_ips()

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
    #proba = model.predict_proba(data)[0]
    #confidence = max(proba)

    if prediction == 0:
        print("Traffic: NORMAL")

    else:
        attack_types = {1: "SYN_FLOOD", 2: "UDP_FLOOD", 3: "ICMP_FLOOD"}
        attack_name = attack_types[prediction]

        print(f"Attack Detected: {attack_name}")	# | Confidence: {confidence:.2f}")

        attacker_ip = max(src_ip_counts, key=src_ip_counts.get)

        action_taken = "None"

        send_to_n8n({
    		"attack_type": attack_name,
    		"src_ip": attacker_ip,
    		"packets_per_sec": packets_per_sec,
    		"unique_src_ips": unique_src_ips
		})

        log_event(
            attack_name,
            attacker_ip,
            packets_per_sec,
            unique_src_ips,
            action_taken
        )

    reset()

"""def block_ip(ip):
    print(f"Blocking IP: {ip}")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])"""
    
"""def block_ip(ip):
    global blocked_ips
    print(f"Blocking IP: {ip} for {BLOCK_DURATION} seconds")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    blocked_ips[ip] = time.time()"""
    
"""def log_event(attack_type, ip, packets_per_sec, unique_src_ips, confidence, action):
    with open("attack_log.csv", "a") as f:
        f.write(
            f"{datetime.datetime.now()},"
            f"{attack_type},"
            f"{ip},"
            f"{packets_per_sec:.2f},"
            f"{unique_src_ips},"
            f"{confidence:.2f},"
            f"{action}\n"
        )"""
        
def log_event(attack_type, ip, packets_per_sec, unique_src_ips, action):
    with open("attack_log.log", "a") as f:
        f.write(
            f"time=\"{datetime.datetime.now()}\" "
            f"attack_type=\"{attack_type}\" "
            f"src_ip=\"{ip}\" "
            f"packets_per_sec={packets_per_sec:.2f} "
            f"unique_src_ips={unique_src_ips} "
            f"action=\"{action}\"\n"
        )
    
"""def unblock_expired_ips():
    global blocked_ips

    current_time = time.time()
    expired_ips = []

    for ip, block_time in blocked_ips.items():
        if current_time - block_time >= BLOCK_DURATION:
            print(f"Unblocking IP: {ip}")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            expired_ips.append(ip)

    for ip in expired_ips:
        del blocked_ips[ip]"""

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
