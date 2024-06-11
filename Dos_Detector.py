from scapy.all import *
import socket

def get_ip_type(ip):
    try:
        ip = ipaddress.ip_address(ip)
        if ip.is_private:
            return "Private"
        else:
            return "Public"
    except ValueError:
        return "Invalid IP"

def get_user_agent(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode(errors='ignore')
        headers = load.split("\r\n")
        for header in headers:
            if "User-Agent:" in header:
                return header.split("User-Agent: ")[1]
    return "Unknown"

def detect_icmp_flood(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        ip_source = packet[IP].src
        ip_type = get_ip_type(ip_source)
        user_agent = get_user_agent(packet)
        print("ICMP (Ping) Flood Detected from: {} ({}), User Agent: {}".format(ip_source, ip_type, user_agent))

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        ip_source = packet[IP].src
        ip_type = get_ip_type(ip_source)
        user_agent = get_user_agent(packet)
        print("SYN Flood Detected from: {} ({}), User Agent: {}".format(ip_source, ip_type, user_agent))

def packet_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=detect_icmp_flood, filter="icmp", store=0) # Filter ICMP traffic
    sniff(prn=detect_syn_flood, filter="tcp", store=0)   # Filter TCP traffic

if __name__ == "__main__":
    packet_sniffer()
