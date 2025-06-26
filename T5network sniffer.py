from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        print(f"[{proto}] {src} -> {dst}")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
